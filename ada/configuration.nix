{ config, ... }:

let
wireguard-net-ip = "10.0.24.2";
moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
pkgs = import <nixpkgs> { overlays = [ moz_overlay (import /home/nightmared/dev/cpnix) ]; };
local_nixpkgs = import /home/nightmared/dev/nixpkgs {};
in
{
  system.stateVersion = "22.11";
  nixpkgs.config.allowUnfree = true;
  system.copySystemConfiguration = true;

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;

  networking.hostName = "ada";
  networking.hostId = "745ecd5b";

  networking.wireless.enable = false;
  networking.networkmanager.enable = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;
  programs.mtr.enable = true;
  networking.wireguard.interfaces = {
    wg0 = {
      ips = [ (wireguard-net-ip + "/32") ];
      privateKeyFile = "/etc/credentials/wireguard.alonzo.key";
      peers = [
        {
          publicKey = "0Ilb5Zya5UivTbaLhul+NPIID0Wwrs4ks59HiEhfwyQ=";
          allowedIPs = [ "10.0.24.0/24" "fd00::1/128" ];
          persistentKeepalive = 25;
          endpoint = "51.158.148.24:51820";
        }
      ];
    };
  };
  networking.bridges = {
    br0 = {
      interfaces = [];
    };
    br1 = {
      interfaces = [];
    };
  };
  networking.interfaces = {
    br1 = {
      ipv4.addresses = [{ address = "10.1.0.1"; prefixLength = 24; }];
    };
  };
  networking.hosts = {
    "10.0.24.1" = [ "nightmared.fr" ];
  };
  services.prometheus.exporters.node = {
    port = 9100;
    listenAddress = wireguard-net-ip;
    enable = true;
    disabledCollectors = [
      "rapl"
    ];
  };
  systemd.services.prometheus-node-exporter = { after = [ "wireguard-wg0.service" ]; };
  systemd.services.availcheck = {
    description = "Measure availbility of http(s) endpoints";
    enable = true;
    serviceConfig = {
      Type = "simple";
      User = "nightmared";
      ExecStart = "${pkgs.availcheck}/bin/availcheck";
      Environment = "XDG_CONFIG_HOME=/home/nightmared/.config/";
      ProtectSystem = "full";
      NoNewPrivileges = true;
    };
  };

  time.timeZone = "Europe/Paris";
  i18n.defaultLocale = "en_US.UTF-8";
  console = {
    font = "Lat2-Terminus16";
    keyMap = "fr";
  };

  services.printing.enable = true;
  hardware.bluetooth.enable = true;
  services.blueman.enable = true;
  services.pipewire = {
    enable = true;
    pulse.enable = true;
  };

  services.xserver.videoDrivers = [ "modesetting" ];
  services.xserver.libinput.enable = true;
  fonts.fonts = with pkgs; [
    noto-fonts noto-fonts-cjk noto-fonts-emoji liberation_ttf fira-code fira-code-symbols source-code-pro powerline-fonts nerdfonts
  ];
  programs.sway = {
    enable = true;
    wrapperFeatures.gtk = true;
    extraPackages = with pkgs; [
      swaylock swayidle wl-clipboard alacritty dunst bemenu grim waybar wf-recorder
    ];
  };
  services.gvfs.enable = true;
  hardware.opengl.extraPackages = with pkgs; [ intel-media-driver ];

  users.users.nightmared = {
    uid = 1000;
    home = "/home/nightmared";
    isNormalUser = true;
    extraGroups = [ "users" "wheel" "kvm" ];
  };


  environment.systemPackages = with pkgs; [
    # Internet thingies
    wget curl latest.firefox-nightly-bin thunderbird chromium liferea
    # base GUI utilities
    gnome3.nautilus gnome3.evince gnome3.file-roller gnome3.eog gnome3.gedit dolphin
    # Password management
    keepassxc 
    # Books
    calibre
    # Theming
    gnome.gnome-themes-extra numix-icon-theme-square numix-icon-theme-circle
    # audio/video
    gimp inkscape ffmpeg_5-full mpd ncmpc vlc pavucontrol local_nixpkgs.mpv
    # fs
    btrfs-progs samba cifs-utils
    # network utilities
    networkmanagerapplet wireshark filezilla nftables nmap tor inetutils borgbackup sshfs bind tcpdump
    # net7
    gopass tinc kubernetes-helm kubectl nodejs_latest
    # virtu
    freerdp virt-viewer virt-manager qemu
    # misc utilities
    usbutils rlwrap socat minicom nvme-cli htop pciutils cryptsetup patchelf file lsof tmux xdg_utils unzip p7zip man-pages pv nload ripgrep imagemagickBig jq
    # for pactl
    pulseaudio
    # monitoring
    fwupd smartmontools lm_sensors powertop intel-gpu-tools iotop dfeet iperf
    # Office
    libreoffice-fresh-unwrapped

    # dev
    python310Full gnumake gdb git neovim lldb rustup
    # reverse
    ghidra-bin
    # C/C++ tools
    clang-tools bear clang-analyzer llvm gcc_multi go golangci-lint binutils
    # Linux stuff
    linuxHeaders linuxPackages_latest.bpftrace linuxPackages_latest.perf
  ];


  documentation.dev.enable = true;
  xdg.portal = {
    enable = true;
    extraPortals = [ pkgs.xdg-desktop-portal-gtk ];
  };
  programs.adb.enable = true;
  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
  };

  boot.kernelPackages = pkgs.linuxKernel.packages.linux_6_0;
  boot.initrd.availableKernelModules = [ "btrfs" "dm_crypt" "xhci_pci" "ahci" "nvme" "usbhid" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];
  boot.kernelParams = [ "intel_iommu=on" ];
  hardware.firmware = with pkgs; [ linux-firmware ];

  fileSystems."/" = {
    device = "/dev/mapper/luks_protected";
    fsType = "btrfs";
    options = [ "noatime" "nodiratime" "compress=zstd:3" "ssd" "discard=async" "space_cache" "subvol=/@/nixos" ];
  };
  fileSystems."/home" = {
    device = "/dev/mapper/luks_protected";
    fsType = "btrfs";
    options = [ "noatime" "nodiratime" "compress=zstd:3" "ssd" "discard=async" "space_cache" "subvol=/@/home" ];
  };

  boot.initrd.luks.devices."luks_protected".device = "/dev/disk/by-uuid/9468e6f1-56b1-4143-aa52-c5089566ac87";

  nixpkgs.hostPlatform = "x86_64-linux";
  powerManagement.cpuFreqGovernor = "performance";
  hardware.cpu.intel.updateMicrocode = config.hardware.enableRedistributableFirmware;

  services.fwupd.enable = true;
  security.tpm2.enable = true;
  services.logind.lidSwitchDocked = "suspend";
}
