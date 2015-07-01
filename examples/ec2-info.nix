{ config, pkgs, ... }:

with pkgs.lib;

{ deployment.ec2.accessKeyId = "sami";
  deployment.ec2.keyPair = "...";
  deployment.ec2.privateKey = mkDefault "/home/sami-bouhlale/.ssh/id_rsa${config.deployment.ec2.region}";
  deployment.ec2.securityGroups = mkDefault [ "default" ];
}
