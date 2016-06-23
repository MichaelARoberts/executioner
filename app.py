from executioner import *
import exe
from hash import *

apiKey = 'SOMEVAL'
filename = 'hashes.csv'

newScan = Hash(apiKey)
newScan.check(filename)
