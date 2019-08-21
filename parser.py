from pwn import *

w = open("./test2.bin","r")
#ww = open("./test3.par","w")

data = w.read()
check = {"a":0,"r":0,"f":0}
checksize = [ 0 for _ in range(0,0x15000) ]
acheck = 0
psize = 0
for i in range(0,len(data)/8):
	idx = i*8
	size = u32(data[idx:idx+3]+"\x00")
	midx = ( (size+7) >> 4 ) + 1;
	op = ord(data[idx+3:idx+4])
	num = u32(data[idx+4:idx+8])
	msize = 0

	if size != 0:
		msize = midx << 4;
		checksize[midx] += 1

	if( op == 0):
		opcode = "alloc"
		check["a"] +=1
		if size > psize:
			acheck += 1
		psize = size
	elif( op == 1):
		opcode = "realloc"
		check["r"] +=1
	elif ( op == 2 ):
	 	opcode = "free"
		check["f"] +=1

	command = "\t"+opcode+"("+str(num)+") / size("+hex(size)+" / "+hex(msize)+")"
	print command

	

print ""
print "allocate:: "+str(check["a"])+" times and cases that next size is more big are "+str(acheck)+" times"
print "reallocate:: "+str(check["r"])+" times"
print "free:: "+str(check["f"])+" times"

print ""
for i in range(0,len(checksize)):
	if(checksize[i] != 0):
		print hex(i<<4)+" use "+str(checksize[i])+" times"



