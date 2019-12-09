

logfile=rxd.log
redir=">> $logfile"
redir=""

echo "$(date) rxd.sh (pid=$$) started"
echo "$(date) rxd.sh (pid=$$) started" $redir

# to kill rxd.sh process _and_ lua process below,
# do 'kill $(pkill -P 123) 123' where 123 is the rxd.sh pid
# 'kill 123' leaves the lua process alive

# ^C must interrupt the lua process below and this rxd.sh process
### hmmm, no.
### trap 'exit 2' INT

while /bin/true ;  do
	lua rxd.lua $redir 2>&1
	status="$?" 
	#  restart if exitcode is 0 or 143 (SIGTERM  ::  15 + 128)
	#    [why adding sigterm here??]
	if [ $status != "0" -a $status != "143" ] ; then 
		break
	fi
	echo "server has exited. sleep 1, then restart."
	sleep 1
done

echo "$(date -Iseconds) rxd.lua exited with code $status" $redir
exit $status




