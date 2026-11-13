MISSING = "missing"

class _Missing:
    """
    Sentinel for attribute that don't exist
    """
    
    def __eq__(self,other):
        return False

    def __ne__(self,other):
        return True

    def __repr__(self):
        return "MISSING"

    __hash__ = None

def resolve(path,request):
    value = request 
    for key in path.split("."):
        if not isinstance(value,dict) or key not in value:
            return MISSING
        value = value[key]
    return value

MISSING = _Missing()

