./woody_woodpacker $1
for i in `seq 2 $2` ; do
	echo $i;
	./woody_woodpacker woody;
done