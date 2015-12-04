import base64
import os
import re

import scrypt


MAP_PATH = os.path.expanduser('~/.config/leap/uuids')


class UserMap(object):

    """
    A persistent mapping between user-ids and uuids.
    """

    # TODO Add padding to the encrypted string

    def __init__(self):
        self._d = {}
        self._lines = set([])
        if os.path.isfile(MAP_PATH):
            self.load()

    def add(self, userid, uuid, passwd):
        """
        Add a new userid-uuid mapping, and encrypt the record with the user password.
        """
        self._add_to_cache(userid, uuid)
        self._lines.add(_encode_uuid_map(userid, uuid, passwd))
        self.dump()

    def _add_to_cache(self, userid, uuid):
        self._d[userid] = uuid

    def load(self):
        """
        Load a mapping from a default file.
        """
        with open(MAP_PATH, 'r') as infile:
            lines = infile.readlines()
            self._lines = set(lines)

    def dump(self):
        """
        Dump the mapping to a default file.
        """
        with open(MAP_PATH, 'w') as out:
            out.write('\n'.join(self._lines))

    def lookup_uuid(self, userid, passwd=None):
        """
        Lookup the uuid for a given userid.

        If no password is given, try to lookup on cache.
        Else, try to decrypt all the records that we know about with the
        passed password.
        """
        if not passwd:
            return self._d.get(userid)

        for line in self._lines:
            guess = _decode_uuid_line(line, passwd)
            if guess:
                record_userid, uuid = guess
                if record_userid == userid:
                    self._add_to_cache(userid, uuid)
                    return uuid

    def lookup_userid(self, uuid):
        """
        Get the userid for the given uuid from cache.
        """
        rev_d = {v: k for (k, v) in self._d.items()}
        return rev_d.get(uuid)


def _encode_uuid_map(userid, uuid, passwd):
    data = 'userid:%s:uuid:%s' % (userid, uuid)
    encrypted = scrypt.encrypt(data, passwd, maxtime=0.05)
    return base64.encodestring(encrypted).replace('\n', '')


def _decode_uuid_line(line, passwd):
    decoded = base64.decodestring(line)
    try:
        maybe_decrypted = scrypt.decrypt(decoded, passwd, maxtime=0.1)
    except scrypt.error:
        return None
    match = re.findall("userid\:(.+)\:uuid\:(.+)", maybe_decrypted)
    if match:
        return match[0]
