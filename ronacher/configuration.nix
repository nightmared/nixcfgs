{ config, pkgs, ... }:

let wireguard-net-ip = "10.0.24.2";
in
{
  imports =
    [
      ./hardware-configuration.nix
      #<home-manager/nixos>
    ];

  environment.enableDebugInfo = true;

  boot.kernelPackages = pkgs.linuxPackages_latest;
  #boot.kernel.features = { debug = true; };
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
    #enable = true;
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
      #linuxPackages_5_11 = nixpkgs-master.linuxPackages_5_11 // {
      #  kernel = nixpkgs-master.linuxPackages_5_11.kernel.override {
      #    separateDebugInfo = true;
      #    dontStrip = true;
      #  };
      #};
      #linuxPackages_latest = self.linuxPackages_5_11;
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

  environment.systemPackages = with pkgs; [
    # Internet thingies
    wget curl latest.firefox-nightly-bin thunderbird chromium google-chrome zoom-us liferea 
    # base GUI utilities
    gnome3.nautilus gnome3.evince gnome3.file-roller calibre gnome3.gedit
    # Theming
    gnome3.networkmanagerapplet gnome3.gnome-themes-standard gnome3.gnome-themes-extra breeze-icons breeze-qt5 dolphin hicolor-icon-theme  numix-icon-theme-square
    # audio/video
    gimp inkscape gnome3.eog v4l-utils ffmpeg-full mpd ncmpc vlc pavucontrol mpv
    # fs
    btrfs-progs nfs-utils samba cifs-utils
    # network utilities
    wireshark filezilla nftables nmap tor inetutils wireguard borgbackup sshfs bind tcpdump
    # legacy cruft
    xorg.xhost xorg.xauth
    # python
    python3Packages.pylint python39Packages.pip python39Packages.setuptools
    # net7
    gopass tinc kubernetes-helm kubectl nodejs_latest 
    # virtu
    freerdp virt-viewer virt-manager qemu woeusb
    # misc utilities
    slurp usbutils rlwrap socat screen minicom nvme-cli htop pciutils cryptsetup patchelf file lsof tmux xdg_utils keepassxc unzip p7zip manpages pv nload ripgrep imagemagickBig jq
    # monitoring
    fwupd availcheck smartmontools lm_sensors powertop intel-gpu-tools iotop dfeet iperf
    # Office
    libreoffice-fresh-unwrapped texlive.combined.scheme-medium

    # dev
    python39Full gnumake gdb git neovim lldb rustup
    # reverse
    ghidra-bin
    # C/C++ tools
    clang-tools bear clang-analyzer llvm gcc_multi go golangci-lint ctags binutils 
    # Linux stuff
    linuxHeaders linuxPackages_5_10.bpftrace linuxPackages_latest.perf
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
      local_ip=$(${pkgs.iproute2}/bin/ip -4 -j a show dev wlo1 | ${pkgs.jq}/bin/jq -r '.[0].addr_info[0].local')
      if [ "$local_ip" = "192.168.1.13" ]; then
        ${pkgs.nfs-utils}/bin/mount.nfs 192.168.1.42:/ /downloads
      else
        ${pkgs.nfs-utils}/bin/mount.nfs 10.0.24.4:/ /downloads
      fi
      ${pkgs.coreutils}/bin/chmod 755 /downloads
    '';
    serviceConfig = {
      Type = "oneshot";
      ExecStop = "${pkgs.util-linux}/bin/umount /downloads";
      RemainAfterExit = "yes";
    };
    requires = [ "wireguard-wg0.service" "networking.target" ];
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

