#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Automatic provisioning of AWS KMS.


import boto
from boto import kms
import nixops.util
import nixops.resources
import nixops.kms_utils


class KmsKeyDefinition(nixops.resources.ResourceDefinition):
    """Definition of an AWS KMS encryption key."""

    @classmethod
    def get_type(cls):
        return "AWS-kms-key"

    def __init__(self, xml):
        nixops.resources.ResourceDefinition.__init__(self, xml)
        self.region = xml.find("attrs/attr[@name='region']/string").get("value")
        self.access_key_id = xml.find("attrs/attr[@name='accessKeyId']/string").get("value")
        self.policy = xml.find("attrs/attr[@name='policy']/string").get("value")
        self.alias = xml.find("attrs/attr[@name='alias']/string").get("value")
        if self.alias == '': self.alias = None
        self.KeyUsage = xml.find("attrs/attr[@name='KeyUsage']/string").get("value")
        self.enabled = xml.find("attrs/attr[@name='enabled']/bool").get("value")
        self.description = xml.find("attrs/attr[@name='description']/string").get("value")
        if self.description == '': self.description = None
        self.grants = xml.find("attrs/attr[@name='grants']/list").get("value")

    def show_type(self):
        return "{0} [{1}]".format(self.get_type(), self.region)


class KmsKeyState(nixops.resources.ResourceState):
    """State of an AWS KMS encryption key."""

    state = nixops.util.attr_property("state", nixops.resources.ResourceState.MISSING, int)
    KeyId = nixops.util.attr_property("kms.KeyId", None)
    region = nixops.util.attr_property("kms.region", None)
    access_key_id = nixops.util.attr_property("kms.accessKeyId", None)
    policy = nixops.util.attr_property("kms.policy", None)
    alias = nixops.util.attr_property("kms.alias", None, str)
    keyUsage = nixops.util.attr_property("kms.keyUsage", None)
    enabled = nixops.util.attr_property("kms.enabled", None)
    description = nixops.util.attr_property("kms.description", None, str)
    grants = nixops.util.attr_property("kms.grants", None)


    @classmethod
    def get_type(cls):
        return "AWS-kms-key"

    def __init__(self, depl, name, id):
        nixops.resources.ResourceState.__init__(self, depl, name, id)
        self._conn = None

    def _exists(self):
        return self.state != self.MISSING

    def show_type(self):
        s = super(KmsKeyState, self).show_type()
        if self._exists(): s = "{0} [{1}]".format(s, self.region)
        return s

    @property
    def resource_id(self):
        return self.KeyId

    def get_definition_prefix(self):
        return "resources.KmsKeys."

    def connect(self):
        if self._conn: 
            return self._conn
        (access_key_id, secret_access_key) = nixops.kms_utils.fetch_aws_secret_key(self.access_key_id)
            #return (access_key_id, secret_access_key)
        self._conn = kms.layer1.KMSConnection(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
        return self._conn


    def update_key_alias(self,alias_name,target_key_id):
        try:
            slef._conn.create_alias(alias_name, target_key_id)
        except boto.kms.exceptions.NotFoundException as e:
            self.logger.log('Setting Alias Failed : wrong key ID (key not found)')
        except boto.exception.JSONResponseError as e :
            if e.error_code == 'ValidationException' :
                self.logger.log('Wrong Alias format, the alias should be like "alias/my_alias". Aliases like alias/aws/.... are reserved for AWS')
        return True

    def update_grants(self,key_id,grantee_principal,retiring_principal=None,operations=None,constraints=None,grant_tokens=None):
        try:
            self._conn.create_grant(key_id,grantee_principal,retiring_principal=None,operations=None,constraints=None,grant_tokens=None)
        except boto.exception.JSONResponseError as e:
            if e.error_code == 'ValidationException' :
                self.logger.log('Setting Grant Failed : unrecognized grantee or unsupported operation')
        return True

    def create(self, defn, check, allow_reboot, allow_recreate):

        self.access_key_id = defn.access_key_id or nixops.kms_utils.get_access_key_id()
        if not self.access_key_id:
            raise Exception("please set ‘accessKeyId’, $EC2_ACCESS_KEY or $AWS_ACCESS_KEY_ID")

        self.connect()

        if self._exists():

            if self.region != defn.region :
                raise Exception("changing the region of an AWS KMS key is not supported")

            if self.policy != None and defn.policy != self.policy:
                raise Exception("You're trying to change the policies of an existing KMS Key, keep it blank to avoid this")

            if defn.alias != None and defn.alias != self.alias:
                raise Exception("You're trying to change the alias of an existing KMS Key, keep it blank to avoid this")

            if defn.grants != None and defn.grants != self.grants:
                raise Exception("You're trying to change the grants of an existing KMS Key, keep it blank to avoid this")

            if defn.description != None and defn.description != self.description:
                raise Exception("You're trying to change the description of an existing KMS Key, keep it blank to avoid this")

            if defn.keyUsage != None and defn.keyUsage != self.keyUsage:
                raise Exception("You're trying to change the usage definition of an existing KMS Key, keep it blank to avoid this")

            if defn.enabled != None and defn.enabled != self.enabled:
                if self.enabled == True :
                    raise Exception("You're trying to disable an existing enabled KMS Key, keep it blank to avoid this")
                if self.enabled == False :
                    raise Exception("You're trying to enable an existing disabled KMS Key, keep it blank to avoid this")
        
        if self.state == self.MISSING:

            if defn.policy != "": policy = defn.policy
            else : policy = 'DEFAULT'

            if defn.description != "": description = defn.description
            else : description = ''

            if defn.keyUsage != "": keyUsage = defn.keyUsage
            else : keyUsage = 'ENCRYPT/DECRYPT'

            if policy and description and keyUsage :
                self.log("Creating new KMS Key for '{2}' usage with '{0}' policies and described by '{1}'...".format(policy, description, keyUsage))

            new_key = self._conn.create_key(policy=defn.policy, description=defn.description, keyUsage=defn.keyUsage)

            with self.depl._db:
                self.state = self.STARTING
                self.region = defn.region
                self.KeyId = new_key['KeyId']
                self.alias = defn.alias
                self.keyUsage = defn.keyUsage
                self.description = defn.description
                self.enabled = defn.enabled
                self.grants = defn.grants
                self.policy = defn.policy

            self.log("KMS KEY ID is ‘{0}’".format(new_key['KeyId']))

        self.update_key_alias(alias_name=defn.alias,target_key_id=new_key['KeyId'])  ############

        self.update_grants(new_key['KeyId'],defn.grants['GranteePrincipal'],defn.grants['retiring_principal'],
            defn.grants['operations'], defn.grants['constraints'], defn.grants['grant_tokens'])

        if self.state == self.STARTING or check:
            nixops.kms_utils.wait_for_key_available(self._conn, self.KeyId, self.logger, states=['Creating', 'Created'])
            self.state = self.UP


    def provide_key(param):
        assert isinstance(param,str)
        conn = self.connect()
        if param != "" :
            if param == "new" :
                key = conn.create_key()
                return key['KeyId']
            else :
                key = nixops.kms_utils.get_kms_key_by_id(conn, param)
                return key['KeyId']
        else :
            key = nixops.kms_utils.get_keyId_by_alias(conn,"alias/aws/ebs")
            return key
