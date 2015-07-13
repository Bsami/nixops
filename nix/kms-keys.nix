{ config, lib, uuid, name, ... }:

with lib;

{

  options = {

    name = mkOption {
      default = "charon-${uuid}-${name}";
      type = types.str;
      description = "Name of the KMS Key.";
    };

    region = mkOption {
      type = types.str;
      description = "Amazon EC2 region.";
    };

    accessKeyId = mkOption {
      type = types.str;
      description = "The AWS Access Key ID.";
    };

    

    keyId = mkOption {
      default = ""; # FIXME: don't set a default
      type = types.str;
      description = "Id of the KMS key. This is set by NixOps.";
    };

    arn = mkOption {
      default = ""; # FIXME: don't set a default
      type = types.str;
      description = "Amazon Resource Name (ARN) of the queue. This is set by NixOps.";
    };

  };

}
