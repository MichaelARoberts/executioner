from executioner import *
import exe
from hash import *

apiKey = '4c05d7680d3d7d946a75a7b36a7799f35325d380437bd625d9c1e5711e1244c8'
filename = 'hashes.csv'

newScan = Hash(apiKey)
newScan.check(filename)
