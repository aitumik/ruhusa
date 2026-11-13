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

def resolve(path,request):
    value = request 
    for key in path.split("."):
        value = value[key]
    return value

MISSING = _Missing()

