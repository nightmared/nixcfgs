# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

let
wireguard-net-ip = "10.0.24.4";
full-hostname = "montaigne.nightmared.fr";
custom_nixpkgs_path = "/root/nixpkgs";
#custom_nixpkgs = import custom_nixpkgs_path {};
in
{
  #disabledModules = [ "services/torrent/transmission.nix" ];

  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
      #(custom_nixpkgs_path + "/nixos/modules/services/torrent/transmission.nix")
      #(custom_nixpkgs_path + "/nixos/modules/security/apparmor/includes.nix")
    ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;

  networking.hostId = "43cea56b";
  networking.hostName = "montaigne";
  networking.nameservers = [ "10.0.24.1" wireguard-net-ip ];
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
     libvirt = super.libvirt.override { iptables = super.iptables-nftables-compat; };
     #transmission = custom_nixpkgs.transmission;
     prosody = super.callPackage (import (custom_nixpkgs_path  + "/pkgs/servers/xmpp/prosody/default.nix")) {};
   })
  ];

  environment.systemPackages = with pkgs; [
    htop wget neovim tmux lm_sensors iotop nvme-cli openssl file git dnsutils tcpdump powertop ripgrep ethtool smartmontools
    iptables-nftables-compat nftables
    tpm2-tools efibootmgr
    # TOR node monitoring
    #nyx
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
      listenPort = 1111;
      peers = [
        {
          publicKey = "0Ilb5Zya5UivTbaLhul+NPIID0Wwrs4ks59HiEhfwyQ=";
          allowedIPs = [ "10.0.24.0/24" ];
          persistentKeepalive = 25;
          endpoint = "51.158.148.24:51820";
        }
	{
	  publicKey = "kMKimPA4NeggV9cEQwKl0PRACiFvnn30HDrhxdSL/CQ=";
	  allowedIPs = [ "10.0.25.2/32" ];
	  persistentKeepalive = 25;
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
    defaults = {
      email = "contact+le@nightmared.fr";
    };
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

  #systemd.services.wstunnel = {
  #  description = "Measure availability of http(s) endpoints";
  #  enable = true;
  #  serviceConfig = {
  #    Type = "simple";
  #    ExecStart = "${pkgs.wstunnel}/bin/wstunnel --server ws://127.0.0.1:80 --restrictTo 127.0.0.1:51820 -v";
  #    ProtectSystem = "full";
  #    NoNewPrivileges = true;
  #    ProtectHome = true;
  #  };
  #  wantedBy = [ "default.target" ];
  #};

  services.transmission = {
    enable = true;
    group = "transmission";
    home = "/var/lib/transmission";
    settings = {
      rpc-bind-address = "127.0.0.1";
      rpc-port = 9091;
      rpc-host-whitelist = "downloads.${full-hostname},localhost";
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
	onlySSL = true;
      };
      "downloads.${full-hostname}" = {
        useACMEHost = full-hostname;
	onlySSL = true;
        basicAuthFile = "/etc/credentials/nginx.basic";
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString config.services.transmission.settings.rpc-port}";
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
	onlySSL = true;
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString config.services.grafana.port}";
          proxyWebsockets = true;
        };
      };
      "syncthing.${full-hostname}" = {
        useACMEHost = full-hostname;
	onlySSL = true;
        locations."/" = {
          proxyPass = "http://${config.services.syncthing.guiAddress}";
          proxyWebsockets = true;
        };
      };
      "radicale.${full-hostname}" = {
        useACMEHost = full-hostname;
	onlySSL = true;
        locations."/" = {
          proxyPass = "http://${builtins.elemAt config.services.radicale.settings.server.hosts 0}";
        };
      };
      "gitlab.${full-hostname}" = {
        useACMEHost = full-hostname;
	onlySSL = true;
        locations."/" = {
          proxyPass = "http://unix:/var/gitlab/state/tmp/sockets/gitlab.socket";
        };
	extraConfig = ''
          root ${pkgs.gitlab}/share/gitlab/public;
          location ~ ^/(assets)/ {
            gzip_static on; # to serve pre-gzipped version
            expires max;
            add_header Cache-Control public;
          }
          error_page 404 /404.html;
          error_page 422 /422.html;
          error_page 500 /500.html;
          error_page 502 /502.html;
          error_page 503 /503.html;
          location ~ ^/(404|422|500|502|503)\.html$ {
            internal;
          }
	'';
      };
      #"vpn.${full-hostname}" = {
      #  useACMEHost = full-hostname;
      #  locations."/" = {
      #    proxyPass = "http://127.0.0.1:8443";
      #    proxyWebsockets = true;
      #  };
      #  #basicAuthFile = "/etc/credentials/vpn.basic";
      #  #extraConfig = ''
      #  #  ssl_client_certificate /etc/credentials/vpn-client-cert.pem;
      #  #  ssl_verify_client on;
      #  #'';
      #};
      #"matrix.${full-hostname}" = {
      #  useACMEHost = full-hostname;
      #  locations."/" = {
      #    proxyPass = "http://${(builtins.elemAt config.services.matrix-synapse.listeners 0).bind_address}:${toString ((builtins.elemAt config.services.matrix-synapse.listeners 0).port)}";
      #  };
      #};


      #"nextcloud.${full-hostname}" = {
      #  useACMEHost = full-hostname;
      #};
    };
  };
  users.users."${config.services.nginx.user}".extraGroups = [ config.services.transmission.group ]; 

  # allow nginx to access te gitlab socket
  systemd.services.gitlab = {
    postStart = ''
      ${pkgs.acl}/bin/setfacl -m u:nginx:rx /var/gitlab/state
      ${pkgs.acl}/bin/setfacl -m u:nginx:rx /var/gitlab/state/tmp
      ${pkgs.acl}/bin/setfacl -m u:nginx:rx /var/gitlab/state/tmp/sockets
      ${pkgs.acl}/bin/setfacl -m u:nginx:rw /var/gitlab/state/tmp/sockets/gitlab.socket
    '';
  };

  #services.nfs.server.enable = true;
  #services.nfs.server.exports = ''
  #  ${config.services.transmission.home}/Downloads 10.0.24.0/24(ro,fsid=0,no_subtree_check)
  #  ${config.services.transmission.home}/Downloads 192.168.1.13/32(ro,fsid=0,no_subtree_check)
  #  #/ 10.42.0.1/32(rw,fsid=0,no_subtree_check,no_root_squash)
  #'';

  networking.nftables = {
    enable = true;
    rulesetFile = "/etc/nftables.conf";
  };

  #services.tor = {
  #  enable = true;
  #  settings = {
  #    ORPort = 143;
  #    DirPort = 9030;
  #    BandwidthBurst = "15M";
  #    BandwidthRate = "5M";
  #    Nickname = "m83fr1";
  #    Address = "tor.${full-hostname}";
  #    ControlPort = [ { port = 9051; } ];
  #    ContactInfo = "Simon Thoby url:nightmared.fr memory:31778 cpu:intel-i3-10100 os:nixos tls:openssl proof:uri-rsa uplinkbw:250 ciissversion:2";
  #  };
  #  relay = {
  #    enable = true;
  #    role = "relay";
  #  };
  #};

  #services.postgresql = {
  #  enable = true;

  #  ensureDatabases = [ "matrix-synapse" ];
  #  ensureUsers = [
  #   {
  #     name = "matrix-synapse";
  #     ensurePermissions."DATABASE \"matrix-synapse\"" = "ALL PRIVILEGES";
  #   }
  #  ];
  #};

  services.unbound = {
    enable = true;
    settings = {
      server = {
        interface = wireguard-net-ip;
	access-control = "10.0.24.0/24 allow";
      };
      remote-control = {
        control-enable = true;
	control-interface = "127.0.0.1";
      };
      forward-zone = {
        name = "nightmared.fr.";
	forward-addr = "51.158.148.24";
      };
    };
  };

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

  services.gitlab = {
    enable = true;
    initialRootPasswordFile = "/etc/credentials/gitlab-initial-password";
    host = "gitlab.${full-hostname}";
    https = true;
    secrets = {
      secretFile = "/etc/credentials/gitlab-db-encryption-secret";
      otpFile = "/etc/credentials/gitlab-otp-secret";
      jwsFile = "/etc/credentials/gitlab-jws-secret";
      dbFile = "/etc/credentials/gitlab-db-secret";
    };
    #registry = {
    #  enable = true;
    #};
  };

  services.gitlab-runner = {
    enable = true;
    services = {
      default = {
        registrationConfigFile = "/etc/credentials/gitlab-runner-registration";
	dockerImage = "debian:11";
      };
    };
  };

  #services.jitsi-meet = {
  #  enable = true;
  #  hostName = "jitsi.nightmared.fr";
  #};
  #services.jitsi-videobridge = {
  #  nat = {
  #    localAddress = "192.168.1.81";
  #    publicAddress = "82.66.80.104";
  #  };
  #};
  ## both jitsi and transmission defines this, overwrite it to prevent a configuration error
  #boot.kernel.sysctl."net.core.rmem_max" = 10485760;


  #services.matrix-synapse = {
  #  enable = true;
  #  no_tls = true;
  #  server_name = "matrix.${full-hostname}:443";
  #  listeners = [
  #    {
  #      bind_address = "127.0.0.1";
  #      port = 8448;
  #      resources = [
  #        {
  #          compress = true;
  #          names = [
  #            "client"
  #            "webclient"
  #          ];
  #        }
  #        {
  #          compress = false;
  #          names = [
  #            "federation"
  #          ];
  #        }
  #      ];
  #      tls = false;
  #      type = "http";
  #      x_forwarded = true;
  #    }
  #  ];
  #  app_service_config_files = [ "/etc/matrix/matterbridge_dev.yml" ];
  #  enable_registration = true;
  #  url_preview_enabled = true;
  #};

  virtualisation.libvirtd = {
    enable = true;
    qemu = {
      ovmf = {
        enable = true;
      };
    };
  };
  users.users."virtboulot" = {
    isNormalUser = true;
    extraGroups = [ "libvirtd" ];
  };

  powerManagement.cpuFreqGovernor = "powersave";

  #security.unprivilegedUsernsClone = true;
  #security.allowSimultaneousMultithreading = true;
  #security.virtualisation.flushL1DataCache = null;

  #security.apparmor.includes."local/bin.ping" = ''
  #  include "${pkgs.apparmorRulesFromClosure {} [pkgs.jemalloc]}"
  #'';

  #security.sudo.extraRules = [
  #  { users = [ "virtboulot" ]; commands = [ { command = "${pkgs.btrfs-progs}/bin/btrfs receive /srv/nas"; options = [ "NOPASSWD" ]; } ]; }
  #];

  #services.openldap = {
  #  enable = true;
  #};

#  services.tinc = {
#    networks."inpnet" = {
#      name = "nightmared2";
#      settings = {
#        Interface = "inpnet";
#        ConnectTo = "orion";
#        Mode = "switch";
#      };
#      rsaPrivateKeyFile = "/etc/tinc/rsa_key.priv";
#      hostSettings = {
#        orion = {
#	  addresses = [
#            { address = "147.127.160.239"; }
#          ];
#	  rsaPublicKey = ''-----BEGIN RSA PUBLIC KEY-----
#MIIBCgKCAQEAxFljoM9ZUQozD8Gdr2VpPDCqNka/DTLc0qicx81AuIE6M36x1Izr
#yH1KG6VO74ynlkthDzxUuuM2fmh50vsTWLLt6j4jvXeWUIz+LjfUAFdH8kex25VN
#eF/2WYtXB+DXP2emxYt5ayMXhUsp8o9yL43UO3AZYPI8AXHLkC634rk0VY1r0wfF
#99iDemWOQpRqjBZiqFYE0aq/6CG5p2ksP+rcXTB2M4Rj+2kN+ReDniqR13AZSGdd
#VwTE7n+kOhHVS1CcyQ3EO3y/QPc/XtxyN1lNm+LMygnifk9NYirW2HSiGtaXDf6U
#3mAur5iv0MoxI+j/SCbNF9W+3yLDfjNTaQIDAQAB
#-----END RSA PUBLIC KEY-----'';
#	};
#        nightmared2 = {
#	  rsaPublicKey = ''-----BEGIN RSA PUBLIC KEY-----
#MIIBCgKCAQEAvhRHcCyV75sJ7nQG7kGQSumlrPN4PY6Nst3yRqMBYsgeUXa7ridk
#G8bX8R7ulJa7NOW/5fsrl0S8W5mjLjRZkDKEgPMhbG5QMfUpP48hVMV6Ljw666sx
#3RUkXUNfi0r9nfSzCm/c54YrLJF/gs9BMDlP1p7FtbEcLpr9E0QgQRe0jIBrXHTH
#dplPoQkymh1Ia0lA/JHiXM6PhPDglC6CA0T9PhQPSuziWa3XyeS9eRz3dEOuOHhe
#R1RG8vWlwlNwPh2uUr6KLAZ6MGLjU6vUoRZqK0AuvLnNRHeNLVswJIy8Y5EgVtvO
#MWi8Q081yaFMdlFweekwSc8K04PXPC8bowIDAQAB
#-----END RSA PUBLIC KEY-----'';
#	};
#      };
#    };
#  };
#
#  systemd.services."tinc.inpnet".path = [ pkgs.iproute2 pkgs.bash pkgs.gawk pkgs.procps ];

  system.stateVersion = "22.05";
}
