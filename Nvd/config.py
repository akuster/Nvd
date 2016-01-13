#

try:
    # local hacking
    import settings as settings
except:
    # deployed location
    import constants as settings

DEBUG = settings.DEBUG
DATABASES = settings.DATABASES
