
he = require 'he'
he.pmem()
print(he.isodate(), he.isodate(nil, true)) -- local time, utc time
exitcode = 0
print("CI-Test. exit code:", exitcode)
os.exit(exitcode)

