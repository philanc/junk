

logfile=rxd.log

echo "$(date) rxd.sh ($$) started"
echo "$(date) rxd.sh ($$) started" >> $logfile

# to kill rxd.sh process _and_ lua process below,
# do 'kill $(pkill -P 123) 123' where 123 is the rxd.sh pid
# 'kill 123' leaves the lua process alive

# ^C must interrupt the lua process below and this rxd.sh process
trap 'exit 2' INT

while /bin/true ;  do
	lua -e "require'rxd'.test()" >> $logfile 2>&1
	status="$?" 
	if [ $status != "0" ] ; then 
		break
	fi
	echo "rxs has exited. sleep 1, then restart."
	sleep 1
done

exit $status




