import codecs

def check_replace(obj, find, replace):
    old_obj = obj
    obj = obj.replace(find, replace)
    assert old_obj != obj, "Failed to find %s in %s to replace" % (obj, find)
    return obj

def unhexify(str):
    return codecs.decode(str.replace(" ", ""), "hex")
