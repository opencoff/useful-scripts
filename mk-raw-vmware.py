#!/usr/bin/env python

import os,os.path,sys, uuid
import random
from os.path import normpath, abspath

def make_uuid(filename):
    u = uuid.uuid5(uuid.NAMESPACE_URL, filename)
    v = [ '%02x' % ord(x) for x in u.bytes ]
    return ' '.join(v[:8]) + '-' + ' '.join(v[8:])


if len(sys.argv) < 2:
    print("usage: %s rawdiskimagefilename [vmdk name]" % sys.argv[0])
    sys.exit(1)

filename = abspath(normpath(sys.argv[1]))
vmdkfilename = "%s.raw" % filename
if len(sys.argv) > 2:
    vmdkfilename = sys.argv[2]

if not os.path.exists(filename):
    print("File not found: %s" % filename)
    sys.exit(1)

r = 0x1a1e708919272998fadcb2aa11faf63fL
r += random.randint(1 << 32, 1 << 40)

vmdk = file(vmdkfilename, 'w')

fsize = os.path.getsize(filename)
total_nsect = fsize / 512
cyl = int(total_nsect)/(255*63)
nsect = cyl*255*63

d = {
    'sects': nsect,
    'wasted_sects': total_nsect - nsect,
    'image': filename,
    'cylinders': cyl,
    'uuid': make_uuid(filename),
    'longcontent': "%x" % r,
    }

vmdk_template = """version=1
CID=fffffffe
parentCID=ffffffff
isNativeSnapshot="no"
createType="monolithicFlat"

# wasted sectors=%(wasted_sects)d
RW %(sects)d FLAT "%(image)s" 0
ddb.geometry.cylinders = "%(cylinders)d"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.adapterType = "ide"
ddb.virtualHWVersion = "7"
ddb.toolsVersion = "8260"
ddb.thinProvisioned = "1"
ddb.encoding = "UTF-8"
ddb.deletable = "true"
ddb.uuid = "%(uuid)s"
ddb.longContentID = "%(longcontent)s"

"""

vmdk.write(vmdk_template % d)

#vmdk.write("version=1\n")
#vmdk.write("CID=c4f57009\n")
#vmdk.write("parentCID=ffffffff\n")
#vmdk.write('isNativeSnapshot="no"\n')
#vmdk.write('createType="monolithicFlat"\n\n')
#vmdk.write('# wasted sectors=%d\n' % (total_nsect-nsect))
#vmdk.write('RW %d FLAT "%s" 0\n' % (nsect, filename))
#vmdk.write('ddb.geometry.cylinders = "%d"\n' % cyl)
#vmdk.write('ddb.geometry.heads = "255"\n')
#vmdk.write('ddb.geometry.sectors = "63"\n')
#vmdk.write('ddb.adapterType = "lsilogic"\n')
#vmdk.write('ddb.virtualHWVersion = "7"\n')
#vmdk.write('ddb.toolsVersion = "8260"\n')
#vmdk.write('ddb.thinProvisioned = "1"\n')
#vmdk.write('ddb.encoding = "UTF-8"\n')
#vmdk.write('ddb.deletable = "true"\n')

vmdk.close()

# vim: notextmode:expandtab:sw=4:ts=4:tw=72:
