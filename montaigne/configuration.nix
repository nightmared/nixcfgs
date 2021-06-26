{ config, pkgs, ... }:

let
wireguard-net-ip = "10.0.24.4";
full-hostname = "montaigne.nightmared.fr";
custom_nixpkgs_path = "/home/test/nixpkgs";
custom_nixpkgs = import custom_nixpkgs_path {};
in
{
  #disabledModules = [ "services/torrent/transmission.nix" ];

  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
      <nixpkgs/nixos/modules/profiles/hardened.nix>
      #(custom_nixpkgs_path + "/nixos/modules/services/torrent/transmission.nix")
    ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;

  networking.hostId = "43cea56b";
  networking.hostName = "montaigne";
  networking.nameservers = [ "10.0.24.1" ];
  networking.resolvconf.enable = pkgs.lib.mkForce false;
  networking.wireless.enable = false;
  networking.firewall.enable = false;

  time.timeZone = "Europe/Paris";

  networking.useDHCP = false;
  networking.interfaces.eno1.useDHCP = true;

  networking.bridges = {
    br0 = {
      interfaces = [];
    };
  };

  i18n.defaultLocale = "en_US.UTF-8";
  console = {
    font = "Lat2-Terminus16";
    keyMap = "fr";
  };

  nixpkgs.config.allowUnfree = true;

  services.zfs.autoSnapshot = {
    enable = false;
    frequent = 2;
    hourly = 4;
    monthly = 2;
  };

  nixpkgs.overlays = [
   (import (builtins.fetchTarball { url = "https://github.com/nightmared/cpnix/archive/main.tar.gz";}))
   (self: super: {
     #libvirt = super.libvirt.override { iptables = super.iptables-nftables-compat; };
     transmission = custom_nixpkgs.transmission;
   })
  ];

  environment.systemPackages = with pkgs; [
    htop wget neovim tmux lm_sensors iotop nvme-cli openssl file git dnsutils tcpdump powertop ripgrep ethtool smartmontools
    iptables-nftables-compat nftables
    tpm2-tools efibootmgr
    # TOR node monitoring
    nyx
    qemu
  ];

  #services.fwupd.enable = true;
  programs.mtr.enable = true;
  services.openssh = {
    enable = true;
    permitRootLogin = "prohibit-password";
  };

  networking.wireguard.interfaces = {
    wg0 = {
      ips = [ (wireguard-net-ip + "/32") ];
      privateKeyFile = "/etc/credentials/wireguard-wg0.key";
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

  services.prometheus.exporters.node = {
    port = 9100;
    listenAddress = wireguard-net-ip;
    enable = true;
    disabledCollectors = [
      "rapl"
    ];
  };
  systemd.services.prometheus-node-exporter = { after = [ "wireguard-wg0.service" ]; };

  security.acme = {
    acceptTerms = true;
    certs = {
      #"kube.nightmared.fr" = {
      #  directory = "/var/lib/acme/kube.nightmared.fr";
      #  credentialsFile = "/etc/credentials/letsencrypt.env";
      #  domain = "*.kube.nightmared.fr";
      #  dnsProvider = "rfc2136";
      #  email = "contact+le@nightmared.fr";
      #  extraDomainNames = [ "kube.nightmared.fr" ];
      #  #server = "https://acme-staging-v02.api.letsencrypt.org/directory";
      #  dnsPropagationCheck = false;
      #  postRun = ''
      #    mkdir -p ${kube-cert-folder}
      #    cp {fullchain.pem,chain.pem,key.pem} ${kube-cert-folder}
      #    chmod -R 744 ${kube-cert-folder}
      #    chmod 755 ${kube-cert-folder}
      #  '';
      #};
      "${full-hostname}" = {
        credentialsFile = "/etc/credentials/letsencrypt.env";
        domain = "*." + full-hostname;
        dnsProvider = "rfc2136";
        email = "contact+le@nightmared.fr";
        extraDomainNames = [ full-hostname ];
        #server = "https://acme-staging-v02.api.letsencrypt.org/directory";
        dnsPropagationCheck = false;
        group = "nginx";
      };
    };
   };

  systemd.services.update-dns = {
    description = "Continuously update the DNS to account for dydns";
    serviceConfig.Type = "oneshot";
    # config for online.net
    #serviceConfig.EnvironmentFile = "/etc/credentials/le-dns.env";
    #${pkgs.le-dns}/bin/le_dns_online --api-key $ONLINE_API_KEY --name $DOMAIN_NAME -t A update --new-value $REAL_IP
    script = ''
      REAL_IP=`${pkgs.curl}/bin/curl -4 -s https://nightmared.fr/ip`
      CUR_IP=`${pkgs.dnsutils}/bin/dig ${full-hostname} +short`

      function updateentry() {
        (echo "server nightmared.fr";
        echo "update delete $1 A";
        echo "update add $1 60 A $2";
        echo "send") | ${pkgs.dnsutils}/bin/nsupdate -k /etc/credentials/letsencrypt.bind
      }

      if [ "$REAL_IP" != "$CUR_IP" ]; then
        updateentry "${full-hostname}" "$REAL_IP"
      fi
    '';
  };

  systemd.timers.update-dns = {
    wantedBy = [ "timers.target" ];
    partOf = [ "update-dns.service" ];
    timerConfig.OnCalendar = "*-*-* *:*:00";
  };

  systemd.services.availcheck = {
    description = "Measure availability of http(s) endpoints";
    enable = true;
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.availcheck}/bin/availcheck";
      Environment = "XDG_CONFIG_HOME=/etc/";
      ProtectSystem = "full";
      NoNewPrivileges = true;
      ProtectHome = true;
    };
    wantedBy = [ "default.target" ];
  };

  systemd.services.mount-backups-folder = {
    description = "Mount the encrypted partition used to store backups";
    enable = true;
    script = ''
      ${pkgs.cryptsetup}/bin/cryptsetup luksOpen /dev/mapper/data_ssd-backups backups --key-file /etc/credentials/ssd-backups-cryptsetup.key --allow-discards
      ${pkgs.util-linux}/bin/mount -t btrfs -o rw,noatime,nodiratime,compress=zstd:3,ssd,discard=async /dev/mapper/backups /srv/backups
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    wantedBy = [ "default.target" ];
  };

  services.syncthing = {
    enable = true;
    dataDir = "/srv/backups/syncthing";
  };
  systemd.services."syncthing".after = ["mount-backups-folder.service"];

  services.transmission = {
    enable = true;
    port = 9091;
    group = "transmission";
    home = "/var/lib/transmission";
    settings = {
      rpc-bind-address = "127.0.0.1";
      rpc-host-whitelist = "downloads.montaigne.nightmared.fr,localhost";
    };
  };

  services.grafana = {
    enable = true;
    domain = "grafana.${full-hostname}";
    port = 3000;
    addr = "127.0.0.1";
    smtp = {
      host = "mail.nightmared.fr:587";
      fromAddress = "operator@nightmared.fr";
      enable = true;
    };
  };

  services.prometheus = {
    enable = true;
    port = 9001;
    globalConfig.scrape_interval = "15s";
    scrapeConfigs = [
      {
        job_name = "node_exporter";
        static_configs = [{
          targets = [ "${wireguard-net-ip}:${toString config.services.prometheus.exporters.node.port}" "10.0.24.1:9100" "10.0.24.2:9100" ];
        }];
      }
      {
        job_name = "availcheck";
        static_configs = [{
          targets = [ "${wireguard-net-ip}:9666" "10.0.24.2:9666" ];
        }];
      }
    ];
    retentionTime = "90d";
    #alertmanager = {
    #  enable = true;
    #  configuration = {
    #    global = {
    #      smtp_smarthost = "mail.nightmared.fr:587";
    #      smtp_from = "operator@montaigne.nightmared.fr";
    #    };
    #    route = {
    #      receiver = "operator";
    #      group_wait = "30s";
    #      group_interval = "5m";
    #      repeat_interval = "3h";
    #    };
    #    receivers = [
    #      {
    #        name = "operator";
    #        email_configs = [
    #          {
    #            to = "operator@nightmared.fr";
    #          }
    #        ];
    #      }
    #    ];
    #  };
    #};
  };

  services.nginx = {
    enable = true;
    user = "nginx";
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    recommendedGzipSettings = true;
    virtualHosts = {
      "${full-hostname}" = {
        useACMEHost = full-hostname;
        forceSSL = true;
      };
      "downloads.${full-hostname}" = {
        useACMEHost = full-hostname;
        forceSSL = true;
        basicAuthFile = "/etc/credentials/nginx.basic";
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString config.services.transmission.port}";
          extraConfig = ''
            proxy_set_header Host "";
          '';
        };
        locations."/downloads/" = {
          alias = "${config.services.transmission.home}/Downloads/";
          extraConfig = ''
            autoindex on;
          '';
        };
      };
      "grafana.${full-hostname}" = {
        useACMEHost = full-hostname;
        forceSSL = true;
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString config.services.grafana.port}";
          proxyWebsockets = true;
        };
      };
      "syncthing.${full-hostname}" = {
        useACMEHost = full-hostname;
        forceSSL = true;
        locations."/" = {
          proxyPass = "http://${config.services.syncthing.guiAddress}";
          proxyWebsockets = true;
        };
      };
      "radicale.${full-hostname}" = {
        useACMEHost = full-hostname;
        forceSSL = true;
        locations."/" = {
          proxyPass = "http://${builtins.elemAt config.services.radicale.settings.server.hosts 0}";
        };
      };

      #"nextcloud.${full-hostname}" = {
      #  useACMEHost = full-hostname;
      #  forceSSL = true;
      #};
    };
  };
  users.users."${config.services.nginx.user}".extraGroups = [ config.services.transmission.group ];

  #services.nfs.server.enable = true;
  #services.nfs.server.exports = ''
  #  #${services.transmission.home}/Downloads 10.0.24.0/24(rw,fsid=0,no_subtree_check,no_root_squash)
  #  #${services.transmission.home}/Downloads 192.168.1.13/32(rw,fsid=0,no_subtree_check,no_root_squash)
  #  / 10.42.0.1/32(rw,fsid=0,no_subtree_check,no_root_squash)
  #'';

  networking.nftables = {
    enable = true;
    rulesetFile = "/etc/nftables.conf";
  };

  services.tor = {
    enable = true;
    settings = {
      ORPort = 143;
      Nickname = "m83fr1";
      Address = "tor.montaigne.nightmared.fr";
      ControlPort = [ { port = 9051; } ];
      DirPort = [ { port = 9030; } ];
      ContactInfo = "Simon Thoby <look me up>";
    };
    relay = {
      enable = true;
      role = "relay";
    };
  };

  #services.nextcloud = {
  #  enable = true;
  #  hostName = "nextcloud.${full-hostname}";
  #  https = true;
  #  autoUpdateApps.enable = true;
  #  autoUpdateApps.startAt = "05:00:00";
  #  config = {
  #    overwriteProtocol = "https";

  #    dbtype = "pgsql";
  #    dbuser = "nextcloud";
  #    dbhost = "/run/postgresql";
  #    dbname = "nextcloud";
  #    dbpassFile = "/etc/credentials/nextcloud-db-password";

  #    adminpassFile = "/etc/credentials/nextcloud-admin-pass";
  #    adminuser = "admin";
  #  };
  #};

  #services.postgresql = {
  #  enable = true;

  #  ensureDatabases = [ "nextcloud" ];
  #  ensureUsers = [
  #   {
  #     name = "nextcloud";
  #     ensurePermissions."DATABASE nextcloud" = "ALL PRIVILEGES";
  #   }
  #  ];
  #};

  #systemd.services."nextcloud-setup" = {
  #  requires = ["postgresql.service"];
  #  after = ["postgresql.service"];
  #};

  services.radicale = {
    enable = true;
    settings = {
      server = {
        hosts = [ "127.0.0.1:5232" ];
      };
      auth = {
        type = "htpasswd";
        htpasswd_filename = "/etc/credentials/radicale.basic";
        htpasswd_encryption = "bcrypt";
      };
      storage = {
        filesystem_folder = "/var/lib/radicale/collections";
      };
    };
  };

  virtualisation.libvirtd = {
    enable = true;
    qemuOvmf = true;
  };
  users.users."virtboulot" = {
    isNormalUser = true;
    extraGroups = [ "libvirtd" ];
  };

  powerManagement.cpuFreqGovernor = "powersave";

  security.unprivilegedUsernsClone = true;
  security.allowSimultaneousMultithreading = true;
  security.virtualisation.flushL1DataCache = null;

  security.sudo.extraRules = [
    { users = [ "virtboulot" ]; commands = [ { command = "${pkgs.btrfs-progs}/bin/btrfs receive /srv/nas"; options = [ "NOPASSWD" ]; } ]; }
  ];


  system.stateVersion = "21.11";
}
