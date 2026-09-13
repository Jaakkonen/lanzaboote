use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::prelude::{OsStrExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::ToString;

use anyhow::{Context, Result, anyhow};
use base32ct::{Base32Unpadded, Encoding};
use nix::unistd::syncfs;
use regex::Regex;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::architecture::SystemdArchitectureExt;
use crate::esp::SystemdEspPaths;
use crate::pcrlock::{PcrlockPaths, lock_pe};
use crate::version::SystemdVersion;
use lanzaboote_tool::architecture::Architecture;
use lanzaboote_tool::esp::EspPaths;
use lanzaboote_tool::gc::Roots;
use lanzaboote_tool::generation::{Generation, GenerationLink};
use lanzaboote_tool::os_release::OsRelease;
use lanzaboote_tool::pe::{self, append_initrd_secrets, lanzaboote_image};
use lanzaboote_tool::signature::Signer;
use lanzaboote_tool::utils::{SecureTempDirExt, file_hash};

pub struct PcrSignature {
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub phases: Vec<String>,
}

pub struct InstallerBuilder {
    lanzaboote_stub: PathBuf,
    arch: Architecture,
    systemd: PathBuf,
    systemd_boot_loader_config: PathBuf,
    configuration_limit: usize,
    bootcounting_initial_tries: u32,
    pcrlock_directory: Option<PathBuf>,
    protected_system: Option<PathBuf>,
    pcr_signature: Option<PcrSignature>,
    esp: PathBuf,
    generation_links: Vec<PathBuf>,
}

impl InstallerBuilder {
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        lanzaboote_stub: impl AsRef<Path>,
        arch: Architecture,
        systemd: PathBuf,
        systemd_boot_loader_config: PathBuf,
        configuration_limit: usize,
        bootcounting_initial_tries: u32,
        pcrlock_directory: Option<PathBuf>,
        protected_system: Option<PathBuf>,
        esp: PathBuf,
        generation_links: Vec<PathBuf>,
    ) -> Self {
        Self {
            lanzaboote_stub: lanzaboote_stub.as_ref().to_path_buf(),
            arch,
            systemd,
            systemd_boot_loader_config,
            configuration_limit,
            bootcounting_initial_tries,
            pcrlock_directory,
            protected_system,
            pcr_signature: None,
            esp,
            generation_links,
        }
    }

    pub fn with_pcr_signature(mut self, signature: Option<PcrSignature>) -> Self {
        self.pcr_signature = signature;
        self
    }

    pub fn build<S: Signer>(self, signer: S) -> Installer<S> {
        let mut gc_roots = Roots::new();
        let esp_paths = SystemdEspPaths::new(self.esp, self.arch);
        gc_roots.extend(esp_paths.iter());

        let pcrlock_paths = self.pcrlock_directory.map(PcrlockPaths::new);
        if let Some(pcrlock_paths) = &pcrlock_paths {
            gc_roots.extend(pcrlock_paths.iter());
        };

        Installer {
            broken_gens: BTreeSet::new(),
            gc_roots,
            lanzaboote_stub: self.lanzaboote_stub,
            systemd: self.systemd,
            systemd_boot_loader_config: self.systemd_boot_loader_config,
            signer,
            configuration_limit: self.configuration_limit,
            bootcounting_initial_tries: self.bootcounting_initial_tries,
            pcrlock_paths,
            protected_system: self.protected_system,
            pcr_signature: self.pcr_signature,
            esp_paths,
            generation_links: self.generation_links,
            arch: self.arch,
        }
    }
}

pub struct Installer<S: Signer> {
    broken_gens: BTreeSet<u64>,
    gc_roots: Roots,
    lanzaboote_stub: PathBuf,
    systemd: PathBuf,
    systemd_boot_loader_config: PathBuf,
    signer: S,
    configuration_limit: usize,
    bootcounting_initial_tries: u32,
    pcrlock_paths: Option<PcrlockPaths>,
    protected_system: Option<PathBuf>,
    pcr_signature: Option<PcrSignature>,
    esp_paths: SystemdEspPaths,
    generation_links: Vec<PathBuf>,
    arch: Architecture,
}

impl<S: Signer> Installer<S> {
    pub fn install(&mut self) -> Result<()> {
        log::info!("Installing Lanzaboote to {:?}...", self.esp_paths.esp);

        let mut links = self
            .generation_links
            .iter()
            .map(GenerationLink::from_path)
            .collect::<Result<BTreeSet<GenerationLink>>>()?;

        let booted_link = self
            .protected_system
            .as_ref()
            .and_then(|p| fs::canonicalize(p).ok())
            .and_then(|protected_system| {
                log::info!("Protecting system {}", protected_system.display());
                links.iter().find(|link| {
                    fs::canonicalize(&link.path).is_ok_and(|resolved| resolved == protected_system)
                })
            })
            .cloned();

        // A configuration limit of 0 means there is no limit.
        if self.configuration_limit > 0 {
            // Only install the number of generations configured. Reverse the list to only take the
            // latest generations and then, after taking them, reverse the list again so that the
            // generations are installed from oldest to newest, i.e. from smallest to largest
            // generation version.
            links = links
                .into_iter()
                .rev()
                .take(self.configuration_limit)
                .rev()
                .collect()
        };

        if let Some(booted_link) = booted_link
            && !links.contains(&booted_link)
        {
            links.pop_first();
            links.insert(booted_link);
        }

        self.install_generations_from_links(links.iter())?;

        self.install_systemd_boot()?;

        if self.broken_gens.is_empty() {
            log::info!("Collecting garbage...");
            // Only collect garbage in these two directories on the ESP. This way, no files that do
            // not belong to the NixOS installation are deleted. Lanzatool takes full control over
            // the esp/EFI/nixos directory and deletes ALL files that it doesn't know about. Dual-
            // or multiboot setups that need files in this directory will NOT work.
            self.gc_roots.collect_garbage(&self.esp_paths.nixos)?;
            // The esp/EFI/Linux directory is assumed to be potentially shared with other distros.
            // Thus, only files that start with "nixos-" are garbage collected (i.e. potentially
            // deleted).
            self.gc_roots
                .collect_garbage_with_filter(&self.esp_paths.linux, |p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("nixos-"))
                })?;
            // Only collect garbage in the Lanzaboote directory because that's the only directory
            // we fully control. Bootloader measurements are not garbage collected because there is
            // only a single installed bootloader version without the possibility of rollbacks.
            if let Some(pcrlock_paths) = &self.pcrlock_paths {
                self.gc_roots.collect_garbage(pcrlock_paths.lanzaboote())?;
            }
        } else {
            // This might produce a ridiculous message if you have a lot of malformed generations.
            let warning = indoc::formatdoc! {"
                Garbage collection is disabled because you have malformed NixOS generations that do
                not contain a readable bootspec document.

                Remove the malformed generations to re-enable garbage collection with
                `nix-env --delete-generations {}`
            ", self.broken_gens.iter().map(ToString::to_string).collect::<Vec<String>>().join(" ")};
            log::warn!("{warning}");
        };

        log::info!("Successfully installed Lanzaboote.");
        Ok(())
    }

    /// Install all generations from the provided `GenerationLinks`.
    fn install_generations_from_links<'a>(
        &mut self,
        links: impl Iterator<Item = &'a GenerationLink>,
    ) -> Result<()> {
        let generations = links
            .filter_map(|link| {
                let generation_result = Generation::from_link(link)
                    .with_context(|| format!("Failed to build generation from link: {link:?}"));

                // Ignore failing to read a generation so that old malformed generations do not stop
                // lzbt from working.
                if generation_result.is_err() {
                    // If there is ANY malformed generation present, completely disable all garbage
                    // collection to protect the old generations from being deleted. The user has
                    // to manually intervene by getting rid of the old generations to re-enable
                    // garbage collection. This safeguard against catastrophic failure in case of
                    // unhandled upstream changes to NixOS.
                    self.broken_gens.insert(link.version);
                }

                generation_result.ok()
            })
            .collect::<Vec<Generation>>();

        if generations.is_empty() {
            // We can't continue, because we would remove all boot entries, if we did.
            return Err(anyhow!(
                "No bootable generations found! Aborting to avoid unbootable system. Please check for Lanzaboote updates!"
            ));
        }

        for generation in generations {
            // The kernels and initrds are content-addressed.
            // Thus, this cannot overwrite files of old generation with different content.
            self.install_generation(&generation)
                .with_context(|| format!("Failed to install generation {}", generation.version))?;

            for specialisation in generation.specialisations.values() {
                self.install_generation(specialisation)
                    .context("Failed to install specialisation.")?;
            }
        }

        // Sync files to persistent storage. This may improve the
        // chance of a consistent boot directory in case the system
        // crashes.
        let boot = File::open(&self.esp_paths.esp).context("Failed to open ESP root directory.")?;
        syncfs(boot).context("Failed to sync ESP filesystem.")?;

        Ok(())
    }

    /// Install the given `Generation`.
    ///
    /// The kernel and initrd are content-addressed, and the stub name identifies the generation.
    /// Hence, this function cannot overwrite files of other generations with different contents.
    /// All installed files are added as garbage collector roots.
    fn install_generation(&mut self, generation: &Generation) -> Result<()> {
        log::debug!("Installing generation {}", generation.version_tag());

        // Companion files belong to the same native generation lifecycle as the
        // kernel and initrd. Publish them even when reusing an installed stub:
        // this restores missing files and registers every retained file as a root.
        for (name, source) in &generation.spec.lanzaboote_extension.boot_files {
            anyhow::ensure!(
                !name.is_empty()
                    && name != "."
                    && name != ".."
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
                "Companion file name must be a single safe filename: {name}"
            );
            let target = self.esp_paths.nixos.join(name);
            // Names must be immutable: never damage an older generation if a
            // caller accidentally reuses a name for different contents.
            if target.exists() {
                anyhow::ensure!(
                    file_hash(source)? == file_hash(&target)?,
                    "Companion file name reused with different contents: {name}"
                );
            } else {
                install(source, &target).context("Failed to publish companion boot file")?;
            }
            self.gc_roots.extend([&target]);
        }
        // Make companions durable before publishing any entry that references them.
        if !generation.spec.lanzaboote_extension.boot_files.is_empty() {
            syncfs(File::open(&self.esp_paths.esp)?)
                .context("Failed to sync companion boot files")?;
        }

        // If the generation is already properly installed, don't overwrite it.
        if self.register_installed_generation(generation)? {
            return Ok(());
        }

        let tempdir = TempDir::new().context("Failed to create temporary directory.")?;
        let bootspec = &generation.spec.bootspec.bootspec;

        // The kernel is a file in /nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-linux-<version>/.
        // (On x86, that file is called bzImage, but other architectures may differ.)
        let kernel_dirname = bootspec
            .kernel
            .parent()
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            .context("Failed to extract the kernel directory name.")?;
        let kernel_version = kernel_dirname
            .rsplit('-')
            .next()
            .context("Failed to extract the kernel version.")?;

        // Install the kernel and record its path on the ESP.
        let kernel_target = self
            .install_nixos_ca(&bootspec.kernel, &format!("kernel-{}", kernel_version))
            .context("Failed to install the kernel.")?;

        // Assemble and install the initrd, and record its path on the ESP.
        // It is not needed to write the initrd in a temporary directory
        // if we do not have any initrd secret.
        let initrd_location = if bootspec.initrd_secrets.is_some() {
            tempdir
                .write_secure_file(
                    fs::read(
                        bootspec
                            .initrd
                            .as_ref()
                            .context("Lanzaboote does not support missing initrd yet.")?,
                    )
                    .context("Failed to read the initrd.")?,
                )
                .context("Failed to copy the initrd to the temporary directory.")?
        } else {
            bootspec
                .initrd
                .clone()
                .expect("Lanzaboote does not support missing initrd yet.")
        };

        if let Some(initrd_secrets_script) = &bootspec.initrd_secrets {
            append_initrd_secrets(initrd_secrets_script, &initrd_location, generation.version)?;
        }
        let initrd_target = self
            .install_nixos_ca(&initrd_location, &format!("initrd-{}", kernel_version))
            .context("Failed to install the initrd.")?;

        // Assemble, sign and install the Lanzaboote stub.
        let os_release = OsRelease::from_generation(generation)
            .context("Failed to build OsRelease from generation.")?;

        let os_release_contents = os_release.to_string();

        let mut kernel_cmdline =
            assemble_kernel_cmdline(&bootspec.init, bootspec.kernel_params.clone());
        let pcr_signature_path = self.pcr_signature_path(generation)?;
        if let Some(path) = &pcr_signature_path {
            kernel_cmdline.push(format!(
                "lanzaboote.pcr_signature=/EFI/nixos/{}",
                path.file_name()
                    .unwrap()
                    .to_str()
                    .context("Invalid PCR signature filename")?
            ));
        }

        let parameters = pe::StubParameters::new(
            &self.lanzaboote_stub,
            &bootspec.kernel,
            &initrd_location,
            &kernel_target,
            &initrd_target,
            &self.esp_paths.esp,
        )?
        .with_cmdline(&kernel_cmdline)
        .with_os_release_contents(os_release_contents.as_bytes());

        let lanzaboote_image_path = lanzaboote_image(&tempdir, &parameters)
            .context("Failed to build and sign lanzaboote stub image.")?;

        if let (Some(signature), Some(target)) = (&self.pcr_signature, &pcr_signature_path) {
            // Read the exact PE sections, including their actual byte lengths.
            let image = fs::read(&lanzaboote_image_path)?;
            let osrel = tempdir.write_secure_file(
                pe::read_section_data(&image, ".osrel").context("Missing .osrel")?,
            )?;
            let cmdline = tempdir.write_secure_file(
                pe::read_section_data(&image, ".cmdline").context("Missing .cmdline")?,
            )?;
            let mut command = Command::new(self.systemd.join("lib/systemd/systemd-measure"));
            command
                .arg("sign")
                .arg(format!("--linux={}", bootspec.kernel.display()))
                .arg(format!("--initrd={}", initrd_location.display()))
                .arg(format!("--osrel={}", osrel.display()))
                .arg(format!("--cmdline={}", cmdline.display()))
                .arg("--bank=sha256")
                .arg(format!("--private-key={}", signature.private_key.display()))
                .arg(format!("--public-key={}", signature.public_key.display()));
            for phase in &signature.phases {
                command.arg(format!("--phase={phase}"));
            }
            let output = command
                .output()
                .context("Failed to run systemd-measure sign")?;
            anyhow::ensure!(
                output.status.success(),
                "systemd-measure sign failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let policy = tempdir.write_secure_file(&output.stdout)?;
            install(&policy, target).context("Failed to publish PCR signature")?;
            self.gc_roots.extend([target]);
            // Publish the policy before the referencing signed boot entry.
            syncfs(File::open(&self.esp_paths.esp)?)?;
        }

        if let Some(pcrlock_paths) = &self.pcrlock_paths {
            let lanzaboote_image_pcrlock =
                pcrlock_paths.lanzaboote_measurement(generation.version_tag());
            lock_pe(&lanzaboote_image_path, &lanzaboote_image_pcrlock)
                .context("Failed to lock Lanzaboote image with systemd-pcrlock")?;
            self.gc_roots.extend([&lanzaboote_image_pcrlock]);
        }

        let stub_target = self.esp_paths.linux.join(
            stub_name(generation, &self.signer, self.bootcounting_initial_tries)
                .context("Get stub name")?,
        );
        self.gc_roots.extend([&stub_target]);
        install_signed(&self.signer, &lanzaboote_image_path, &stub_target)
            .context("Failed to install the Lanzaboote stub.")?;

        Ok(())
    }

    fn pcr_signature_path(&self, generation: &Generation) -> Result<Option<PathBuf>> {
        let Some(signature) = &self.pcr_signature else {
            return Ok(None);
        };
        let mut hash = Sha256::new();
        hash.update(fs::read(&signature.public_key)?);
        for phase in &signature.phases {
            hash.update([0]);
            hash.update(phase.as_bytes());
        }
        Ok(Some(self.esp_paths.nixos.join(format!(
            "{}-{}.pcrsig",
            stub_prefix(generation, &self.signer)?,
            Base32Unpadded::encode_string(&hash.finalize())
        ))))
    }

    /// Register the files of an already installed generation as garbage collection roots.
    ///
    /// The bool indicates whether the generation was properly installed,
    /// if this function returns Ok(false) the generation should be (re-)installed.
    fn register_installed_generation(&mut self, generation: &Generation) -> Result<bool> {
        // A boot loader entry file name may contain a plus (+) followed by a number.
        // This may optionally be followed by a minus (-) followed by a second number.
        // The dot (.) and file name suffix (conf or efi) must immediately follow.
        // The first number is the amount of times the boot entry should (still) be tried.
        // The second number is the amount of times the boot entry has been tried unsuccessfully.
        // See https://uapi-group.org/specifications/specs/boot_loader_specification/#boot-counting
        let pattern = format!(
            r"^{}(\+\d+(-\d+)?)?\.efi$",
            regex::escape(&stub_prefix(generation, &self.signer)?)
        );
        let regex =
            Regex::new(&pattern).context("Failed to construct regex to read stubs from ESP")?;

        // An Err returned from this function means that we couldn't properly read
        // the different files belonging to this generation, so it should be reinstalled
        if let Ok((stub_target, kernel_path, initrd_path)) = self.read_installed_generation(regex) {
            let stub = fs::read(&stub_target)?;
            let cmdline = std::str::from_utf8(
                pe::read_section_data(&stub, ".cmdline").context("Missing .cmdline")?,
            )?;
            let installed_policy = cmdline
                .split_ascii_whitespace()
                .rev()
                .find_map(|arg| arg.strip_prefix("lanzaboote.pcr_signature="))
                .map(|path| -> Result<PathBuf> {
                    let name = path
                        .strip_prefix("/EFI/nixos/")
                        .context("PCR signature is outside EFI/nixos")?;
                    anyhow::ensure!(
                        name.ends_with(".pcrsig")
                            && name
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
                        "Invalid PCR signature filename"
                    );
                    Ok(self.esp_paths.nixos.join(name))
                })
                .transpose()?;
            if let Some(expected) = self.pcr_signature_path(generation)? {
                if installed_policy.as_ref() != Some(&expected) {
                    return Ok(false);
                }
            }
            if let Some(policy) = installed_policy {
                if !policy.is_file() {
                    return Ok(false);
                }
                self.gc_roots.extend([&policy]);
            }
            self.gc_roots
                .extend([&stub_target, &kernel_path, &initrd_path]);
            // Do not return yet, we still need to check the existence of the pcrlock measurements.
        } else {
            return Ok(false);
        }

        if let Some(pcrlock_paths) = &self.pcrlock_paths {
            let lanzaboote_image_pcrlock =
                pcrlock_paths.lanzaboote_measurement(generation.version_tag());
            if lanzaboote_image_pcrlock.exists() {
                self.gc_roots.extend([&lanzaboote_image_pcrlock]);
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    // Read the stub, kernel and initrd paths belonging to the generation matching the given regex.
    //
    // The regex is used to find the generation based on the stub filename.
    // The regex should only match a single generation on disk.
    // An Err returned from this function means that we couldn't properly read
    // the different files belonging to this generation, so it should be reinstalled
    fn read_installed_generation(&mut self, regex: Regex) -> Result<(PathBuf, PathBuf, PathBuf)> {
        // Read the esp dir and find the entry that corresponds to the generation.
        // There should only be one such entry.
        let stub_target = fs::read_dir(&self.esp_paths.linux)?
            .filter_map(|maybe_entry| {
                if let Ok(entry) = maybe_entry
                    && let Ok(name) = entry.file_name().into_string()
                    && regex.is_match(&name)
                {
                    return Some(entry.path());
                }
                None
            })
            .next()
            .context("While determining stub name")?;

        let stub = fs::read(&stub_target)
            .with_context(|| format!("Failed to read the stub: {}", stub_target.display()))?;
        let kernel_path = resolve_efi_path(
            &self.esp_paths.esp,
            pe::read_section_data(&stub, ".linux").context("Missing kernel path.")?,
        )?;
        let initrd_path = resolve_efi_path(
            &self.esp_paths.esp,
            pe::read_section_data(&stub, ".initrd").context("Missing initrd path.")?,
        )?;

        if !kernel_path.exists() || !initrd_path.exists() {
            anyhow::bail!("Missing kernel or initrd.");
        }

        Ok((stub_target, kernel_path, initrd_path))
    }

    /// Install a content-addressed file to the `EFI/nixos` directory on the ESP.
    ///
    /// It is automatically added to the garbage collector roots.
    /// The full path to the target file is returned.
    fn install_nixos_ca(&mut self, from: &Path, label: &str) -> Result<PathBuf> {
        let hash = file_hash(from).context("Failed to read the source file.")?;
        let to = self.esp_paths.nixos.join(format!(
            "{}-{}.efi",
            label,
            Base32Unpadded::encode_string(&hash)
        ));
        self.gc_roots.extend([&to]);
        install(from, &to)?;
        Ok(to)
    }

    /// Install systemd-boot to ESP.
    ///
    /// systemd-boot is only updated when a newer version is available OR when the currently
    /// installed version is not signed. This enables switching to Lanzaboote without having to
    /// manually delete previous unsigned systemd-boot binaries and minimizes the number of writes
    /// to the ESP.
    ///
    /// Checking for the version also allows us to skip buggy systemd versions in the future.
    fn install_systemd_boot(&self) -> Result<()> {
        let systemd_boot = self
            .systemd
            .join("lib/systemd/boot/efi")
            .join(self.arch.systemd_filename());

        let newer_systemd_boot_available =
            newer_systemd_boot(&systemd_boot, &self.esp_paths.efi_fallback)?
                || newer_systemd_boot(&systemd_boot, &self.esp_paths.systemd_boot)?;
        if newer_systemd_boot_available {
            log::info!("Updating systemd-boot...")
        };

        let systemd_boot_is_signed = self.signer.verify_path(&self.esp_paths.efi_fallback)?
            && self.signer.verify_path(&self.esp_paths.systemd_boot)?;
        if !systemd_boot_is_signed {
            log::warn!("systemd-boot is not signed. Replacing it with a signed binary...")
        };

        // If Measured Boot is not enabled (i.e. `pcrlock_paths` is `None`), this should be true.
        // Otherwise we will always re-install systemd-boot if Measured Boot is disabled.
        let measurement_exists = self
            .pcrlock_paths
            .as_ref()
            .is_none_or(|p| p.bootloader_measurement("current").exists());
        if !measurement_exists {
            log::warn!(
                "systemd-boot has not been measured. Creating measurement and re-installing..."
            )
        };

        if newer_systemd_boot_available || !systemd_boot_is_signed || !measurement_exists {
            // The following assumes that the "current" measurement before an update
            // always refers to the bootloader that was used for startup of the system
            // that performs the bootloader update.
            // This means that a reboot must happen between two consecutive bootloader
            // updates, otherwise we cannot produce a policy that covers PCR4 with this
            // approach.
            if let Some(pcrlock_paths) = &self.pcrlock_paths {
                // Path to measurement that was used prior to this implementation during an update,
                // so the file should not exist *after* an update. In case it is still present, we
                // simply delete it, because it would otherwise be picked up by pcrlock.
                let legacy_path = pcrlock_paths.bootloader_measurement("next");
                if legacy_path.exists() {
                    log::info!("Found leftover measurement file, removing.");
                    fs::remove_file(&legacy_path).with_context(|| {
                        format!(
                            "Failed to remove leftover measurement file {}",
                            legacy_path.display()
                        )
                    })?;
                };

                let previous = pcrlock_paths.bootloader_measurement("previous");
                // Path to measurement of the new loader PE that will override the current one
                let current = pcrlock_paths.bootloader_measurement("current");

                if current.exists() {
                    fs::rename(&current, &previous).with_context(|| {
                        format!(
                            "Failed to rename {} to {}",
                            current.display(),
                            previous.display()
                        )
                    })?;
                }

                // Measure the bootloader we are about to install as "current".
                lock_pe(&systemd_boot, &current)
                    .context("Failed to lock systemd-boot image with systemd-pcrlock")?;
            }

            for to in [&self.esp_paths.efi_fallback, &self.esp_paths.systemd_boot] {
                log::info!("Installing {}", to.display());
                install_signed(&self.signer, &systemd_boot, to)
                    .with_context(|| format!("Failed to install systemd-boot binary to: {to:?}"))?;
            }
        }

        install(
            &self.systemd_boot_loader_config,
            &self.esp_paths.systemd_boot_loader_config,
        )
        .with_context(|| {
            format!(
                "Failed to install systemd-boot loader.conf to {:?}",
                &self.esp_paths.systemd_boot_loader_config
            )
        })?;

        Ok(())
    }
}

/// Translate an EFI path to an absolute path on the mounted ESP.
fn resolve_efi_path(esp: &Path, efi_path: &[u8]) -> Result<PathBuf> {
    Ok(esp.join(std::str::from_utf8(&efi_path[1..])?.replace('\\', "/")))
}

/// Compute the file name to be used for the stub of a certain generation, signed with the given key.
///
/// The generated name is input-addressed by the toplevel corresponding to the generation and the public part of the signing key.
fn stub_name<S: Signer>(
    generation: &Generation,
    signer: &S,
    bootcounting_tries: u32,
) -> Result<PathBuf> {
    stub_prefix(generation, signer).map(|prefix| {
        PathBuf::from(if bootcounting_tries > 0 {
            format!("{}+{}.efi", prefix, bootcounting_tries)
        } else {
            format!("{}.efi", prefix)
        })
    })
}

fn stub_prefix<S: Signer>(generation: &Generation, signer: &S) -> Result<String> {
    let bootspec = &generation.spec.bootspec.bootspec;
    let public_key = signer.get_public_key()?;
    let stub_inputs = [
        // Generation numbers can be reused if the latest generation was deleted.
        // To detect this, the stub path depends on the actual toplevel used.
        ("toplevel", bootspec.toplevel.0.as_os_str().as_bytes()),
        // If the key is rotated, the signed stubs must be re-generated.
        // So we make their path depend on the public key used for signature.
        ("public_key", &public_key),
    ];
    let stub_input_hash = Base32Unpadded::encode_string(&Sha256::digest(
        serde_json::to_string(&stub_inputs).unwrap(),
    ));
    if let Some(specialisation_name) = &generation.specialisation_name {
        Ok(format!(
            "nixos-generation-{}-specialisation-{}-{}",
            generation, specialisation_name, stub_input_hash
        ))
    } else {
        Ok(format!(
            "nixos-generation-{}-{}",
            generation, stub_input_hash
        ))
    }
}

/// Install a PE file. The PE gets signed in the process.
///
/// If the file already exists at the destination, it is overwritten.
///
/// This is implemented as an atomic write. The file is first written to the destination with a
/// `.tmp` suffix and then renamed to its final name. This is atomic, because a rename is an atomic
/// operation on POSIX platforms.
fn install_signed(signer: &impl Signer, from: &Path, to: &Path) -> Result<()> {
    log::debug!("Signing and installing {to:?}...");
    let to_tmp = to.with_extension(".tmp");
    ensure_parent_dir(&to_tmp);
    signer
        .sign_and_copy(from, &to_tmp)
        .with_context(|| format!("Failed to copy and sign file from {from:?} to {to:?}"))?;
    // A signer may report success even when its output could not be written
    // (for example, sbsign on a full ESP). Never publish an invalid image.
    if !signer
        .verify_path(&to_tmp)
        .with_context(|| format!("Failed to verify signed temporary file {to_tmp:?}"))?
    {
        return Err(anyhow!("Invalid signature on temporary file {to_tmp:?}"));
    }
    File::open(&to_tmp)
        .with_context(|| format!("Failed to open signed temporary file {to_tmp:?}"))?
        .sync_all()
        .with_context(|| format!("Failed to sync signed temporary file {to_tmp:?}"))?;
    fs::rename(&to_tmp, to).with_context(|| {
        format!("Failed to move temporary file {to_tmp:?} to final location {to:?}")
    })?;
    Ok(())
}

/// Install an arbitrary file.
///
/// The file is only copied if
///     (1) it doesn't exist at the destination or,
///     (2) the hash of the file at the destination does not match the hash of the source file.
fn install(from: &Path, to: &Path) -> Result<()> {
    if !to.exists() || file_hash(from)? != file_hash(to)? {
        force_install(from, to)?;
    }
    Ok(())
}

/// Forcibly install an arbitrary file.
///
/// If the file already exists at the destination, it is overwritten.
///
/// This function is only designed to copy files to the ESP. It sets the permission bits of the
/// file at the destination to 0o755, the expected permissions for a vfat ESP. This is useful for
/// producing file systems trees which can then be converted to a file system image.
fn force_install(from: &Path, to: &Path) -> Result<()> {
    log::debug!("Installing {to:?}...");
    ensure_parent_dir(to);
    atomic_copy(from, to)?;
    set_permission_bits(to, 0o755)
        .with_context(|| format!("Failed to set permission bits to 0o755 on file: {to:?}"))?;
    Ok(())
}

fn assemble_kernel_cmdline(init: &Path, kernel_params: Vec<String>) -> Vec<String> {
    let init_string = String::from(
        init.to_str()
            .expect("Failed to convert init path to string"),
    );
    let mut kernel_cmdline: Vec<String> = vec![format!("init={}", init_string)];
    kernel_cmdline.extend(kernel_params);
    kernel_cmdline
}

/// Atomically copy a file.
///
/// First, the content is written to a temporary file (with a `.tmp` extension).
/// Then, this file is synced, to ensure its data and metadata are fully on disk before continuing.
/// In the last step, the temporary file is renamed to the final destination.
///
/// Due to the deficiencies of FAT32, it is possible for the filesystem to become corrupted after power loss.
/// It is not possible to fully defend against this situation, so this operation is not actually fully atomic.
/// However, in all other cases, the target file is either present with its correct content or not present at all.
fn atomic_copy(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_extension(".tmp");
    {
        let mut from_file =
            File::open(from).with_context(|| format!("Failed to read the source file {from:?}"))?;
        let mut tmp_file = File::create(&tmp)
            .with_context(|| format!("Failed to create the temporary file {tmp:?}"))?;
        std::io::copy(&mut from_file, &mut tmp_file).with_context(|| {
            format!("Failed to copy from {from:?} to the temporary file {tmp:?}")
        })?;
        tmp_file
            .sync_all()
            .with_context(|| format!("Failed to sync the temporary file {tmp:?}"))?;
    }
    fs::rename(&tmp, to)
        .with_context(|| format!("Failed to move temporary file {tmp:?} to target {to:?}"))
}

/// Set the octal permission bits of the specified file.
fn set_permission_bits(path: &Path, permission_bits: u32) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("File {path:?} doesn't have any metadata"))?
        .permissions();
    perms.set_mode(permission_bits);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on {path:?}"))
}

// Ensures the parent directory of an arbitrary path exists
fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
}

/// Determine if a newer systemd-boot version is available.
///
/// "Newer" can mean
///   (1) no file exists at the destination,
///   (2) the file at the destination is malformed,
///   (3) a binary with a higher version is available.
fn newer_systemd_boot(from: &Path, to: &Path) -> Result<bool> {
    // If the file doesn't exists at the destination, it should be installed.
    if !to.exists() {
        return Ok(true);
    }

    // If the version from the source binary cannot be read, something is irrecoverably wrong.
    let from_version = SystemdVersion::from_systemd_boot_binary(from)
        .with_context(|| format!("Failed to read systemd-boot version from {from:?}."))?;

    // If the version cannot be read from the destination binary, it is malformed. It should be
    // forcibly reinstalled.
    let to_version = match SystemdVersion::from_systemd_boot_binary(to) {
        Ok(version) => version,
        _ => return Ok(true),
    };

    Ok(from_version > to_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanzaboote_tool::signature::LocalKeyPair;
    use std::os::unix::fs::symlink;

    #[test]
    fn failed_signed_write_does_not_publish_or_replace_image() -> Result<()> {
        let systemd = PathBuf::from(std::env::var("TEST_SYSTEMD")?);
        let architecture =
            Architecture::from_nixos_system(&format!("{}-linux", std::env::consts::ARCH))?;
        let source = systemd
            .join("lib/systemd/boot/efi")
            .join(architecture.systemd_filename());
        let signer = LocalKeyPair::new(
            Path::new("tests/fixtures/uefi-keys/db.pem"),
            Path::new("tests/fixtures/uefi-keys/db.key"),
        );

        for existing in [false, true] {
            let directory = tempfile::tempdir()?;
            let destination = directory.path().join("boot.efi");
            let previous = if existing {
                install_signed(&signer, &source, &destination)?;
                assert!(signer.verify_path(&destination)?);
                Some(fs::read(&destination)?)
            } else {
                None
            };

            // sbsign 0.9.5 exits successfully even when writing to /dev/full.
            // This reproduces ENOSPC without a privileged filesystem mount.
            symlink("/dev/full", destination.with_extension(".tmp"))?;
            assert!(install_signed(&signer, &source, &destination).is_err());
            if let Some(previous) = previous {
                assert_eq!(fs::read(&destination)?, previous);
                assert!(signer.verify_path(&destination)?);
            } else {
                assert!(!destination.exists());
            }
        }
        Ok(())
    }
}
