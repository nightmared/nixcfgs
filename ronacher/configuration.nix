{ config, pkgs, ... }:

let wireguard-net-ip = "10.0.24.2";
in
{
  imports =
    [
      ./hardware-configuration.nix
      #<home-manager/nixos>
    ];

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking.hostName = "ronacher"; # Define your hostname.
  networking.wireless.enable = false;
  networking.networkmanager.enable = true;
  networking.firewall.enable = false;
  networking.extraHosts = ''
    147.127.160.30 grafana.k8s.inpt.fr
  '';

  networking.hostId = "745ecd5b";

  time.timeZone = "Europe/Paris";

  i18n.defaultLocale = "en_US.UTF-8";
  console = {
    font = "Lat2-Terminus16";
    keyMap = "fr";
  };
  services.xserver.layout = "fr";

  # Enable CUPS to print documents.
  services.printing.enable = true;

  hardware.bluetooth.enable = true;
  hardware.bluetooth.config = {
    General = {
      Enable = "Source,Sink,Media,Socket";
    };
  };
  services.blueman.enable = true;

  sound.enable = true;
  hardware.pulseaudio = {
    enable = true;
    extraModules = [ pkgs.pulseaudio-modules-bt ];
    package = pkgs.pulseaudioFull;
    extraConfig = "
      load-module module-switch-on-connect
    ";
  };
  nixpkgs.config.pulseaudio = true;

  services.xserver.videoDrivers = [ "modesetting" "i915" "iris" ];
  services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.nightmared = {
    uid = 1000;
    home = "/home/nightmared";
    isNormalUser = true;
    extraGroups = [ "users" "wheel" "audio" "video" "kvm" "network" "networkmanager" "adbusers" "wireshark" "libvirtd" ];
  };
  #home-manager.users.nightmared = { pkgs, ... }: {

  #};
  #home-manager.useGlobalPkgs = true;

  nixpkgs.config.allowUnfree = true;

  services.zfs.autoSnapshot = {
    enable = true;
    frequent = 2;
    hourly = 4;
    monthly = 2;
  };

  nixpkgs.overlays =
  let
    moz-rev = "master";
    moz-url = builtins.fetchTarball { url = "https://github.com/mozilla/nixpkgs-mozilla/archive/${moz-rev}.tar.gz";};
    nightlyOverlay = (import "${moz-url}/firefox-overlay.nix");
    nixpkgs-master = import /home/nightmared/dev/nixpkgs {};
    masterOverlay = self: super: rec {
      #python3 = super.python3.override {
      #  packageOverrides = selfx: superx:  {
      #    feedparser = nixpkgs-master.python3Packages.feedparser;
      #    llfuse = nixpkgs-master.python3Packages.llfuse;
      #  };
      #};
      #python3Packages = python3.pkgs;
      #yj = nixpkgs-master.yj;
      #calibre = nixpkgs-master.calibre;
      #libvirt = super.libvirt.override { iptables = super.iptables-nftables-compat; };
      #virtualbox = nixpkgs-master.virtualbox;
      #mpv = nixpkgs-master.mpv;
      #podman-unwrapped = nixpkgs-master.podman-unwrapped;
    };

  in [
    nightlyOverlay
    masterOverlay
    (import /home/nightmared/dev/cpnix)
  ];

  virtualisation.libvirtd = {
    #enable = true;
    qemuOvmf = true;
  };
  #programs.dconf.enable = true;

  environment.systemPackages = let arcan = (pkgs.callPackage (import /home/nightmared/dev/arcan/Arcan.nix) {}); in with pkgs; [
    wget tmux curl thunderbird evince neovim chromium google-chrome llvm zoom-us nvme-cli htop smartmontools pciutils gnome3.nautilus gnome3.eog gnome3.evince gnome3.file-roller gimp inkscape gnome3.networkmanagerapplet cryptsetup wireguard mpd ncmpc qemu patchelf gcc_multi go clang-analyzer file gnome3.gnome-themes-standard gnome3.gnome-themes-extra pavucontrol lsof git nodejs_latest latest.firefox-nightly-bin xdg_utils lm_sensors powertop hicolor-icon-theme keepassxc unzip p7zip python39Full gnumake gdb fwupd libreoffice-fresh-unwrapped numix-icon-theme-square glib calibre gnome3.gedit borgbackup slurp sshfs intel-gpu-tools iotop dfeet manpages pv nload ripgrep imagemagickBig texlive.combined.scheme-medium gopass xournal virt-manager kubectl tinc ctags binutils lldb bind vlc nfs-utils liferea rustup iperf linuxPackages.perf niv jq
    v4l-utils ffmpeg-full btrfs-progs
    woeusb
    musl openssl minio wireshark filezilla
    breeze-icons breeze-qt5 dolphin
    xorg.xhost xorg.xauth
    python3Packages.pylint python39Packages.pip python39Packages.setuptools
    usbutils
    kubernetes-helm
    freerdp
    tcpdump
    nftables
    virt-viewer
    mpv
    samba cifs-utils
    nmap
    #s3s
    availcheck
    tor
    inetutils
    #le-dns
    ghidra-bin
    rlwrap socat screen minicom
    clang-tools bear
    golangci-lint
    #emacs
  ];

  documentation.dev.enable = true;
  services.flatpak.enable = true;
  xdg.portal = {
    enable = true;
    extraPortals = [ pkgs.xdg-desktop-portal-gtk ];
  };

  programs.adb.enable = true;

  fonts.fonts = with pkgs; [
    noto-fonts noto-fonts-cjk noto-fonts-emoji liberation_ttf fira-code fira-code-symbols source-code-pro powerline-fonts nerdfonts
  ];

  programs.mtr.enable = true;
  programs.gnupg.agent = {
    enable = true;
    enableSSHSupport = true;
  };
  programs.sway = {
    enable = true;
    wrapperFeatures.gtk = true;
    extraPackages = with pkgs; [
      swaylock swayidle wl-clipboard alacritty dunst bemenu grim waybar wf-recorder
    ];
  };
  programs.light.enable = true;

  networking.wireguard.interfaces = {
    wg0 = {
      ips = [ (wireguard-net-ip + "/32") ];
      privateKeyFile = "/etc/wireguard/wg0.key";
      peers = [
        {
          publicKey = "0Ilb5Zya5UivTbaLhul+NPIID0Wwrs4ks59HiEhfwyQ=";
          allowedIPs = [ "10.0.24.0/24" ];
          persistentKeepalive = 25;
          endpoint = "51.158.148.24:51820";
        }
      ];
    };
  };

  services.fwupd.enable = true;

  services.logind.lidSwitchDocked = "suspend";
  powerManagement.resumeCommands = ''
    export WAYLAND_DISPLAY=$(${pkgs.coreutils}/bin/cat /home/nightmared/.local/wayland-display)
    export XDG_RUNTIME_DIR=/run/user/$(${pkgs.coreutils}/bin/id -u nightmared)
    ${pkgs.su}/bin/su nightmared -c "${pkgs.swaylock}/bin/swaylock -i /home/nightmared/pictures/wall/download2.jpg"
  '';

  systemd.services.edid-override = {
    enable = true;
    description = "Override the edid of DP-1";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.bash}/bin/sh -c '${pkgs.coreutils}/bin/cat /home/nightmared/.config/edid/edid-dvi > /sys/kernel/debug/dri/0/DP-1/edid_override'";
    };
    wantedBy = [ "multi-user.target" ];
  };


  systemd.services.nfs-mount = {
    enable = true;
    description = "Mount the remote nfs folder";
    script = ''
      ${pkgs.nfs-utils}/bin/mount.nfs 10.0.24.4:/ /downloads
      ${pkgs.coreutils}/bin/chmod 755 /downloads
    '';
    serviceConfig = {
      Type = "oneshot";
      ExecStop = "${pkgs.util-linux}/bin/umount /downloads";
      RemainAfterExit = "yes";
    };
    requires = [ "wireguard-wg0.service" ];
    wantedBy = [ "multi-user.target" ];
  };


  security.pam.loginLimits = [
    {
      domain = "@users";
      type   = "-";
      item   = "memlock";
      value  = "unlimited";
    }
  ];


  #virtualisation.virtualbox.host.enable = true;
  #virtualisation.virtualbox.host.enableExtensionPack = true;
  users.extraGroups.vboxusers.members = [ "nightmared" ];

  #nix = {
  # package = pkgs.nixFlakes;
  # extraOptions = ''
  #   experimental-features = nix-command flakes
  # '';
  #};

  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
  };

  networking.bridges = {
    br0 = {
      interfaces = [];
    };
    br1 = {
      interfaces = [];
    };
  };

  #powerManagement.cpuFreqGovernor = "schedutil";

  networking.interfaces = {
    br1 = {
      ipv4.addresses = [{ address = "10.1.0.1"; prefixLength = 24; }];
    };
  };

  #networking.nat.enable = true;
  #networking.nat.internalInterfaces = ["ve-+"];
  #networking.nat.externalInterface = "wlo1";
  #networking.networkmanager.unmanaged = [ "interface-name:ve-*" ];

  #containers.web = {
  #  extraFlags = [ "--bind-ro=/tmp/.X11-unix" ];
  #  config = import /var/lib/containers/web/etc/nixos/configuration.nix;
  #  interfaces = [ "br0" ];
  #};

  nix.useSandbox = true;

  boot.kernel.sysctl = { "net.ipv4.conf.wlo1.forwarding"=1; "kernel.sysrq"=112; "fs.inotify.max_user_watches"=524288; };

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

  services.davfs2 = {
    enable = true;
  };

  services.gvfs.enable = true;

  system.stateVersion = "21.03";
}

