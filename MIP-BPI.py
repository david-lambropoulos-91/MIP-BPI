from Tkinter import *
import idautils
from idaapi import *
import binascii
import time

time.sleep(4)

root = Tk()

#Keeping track of buttons
var = IntVar()
var1 = IntVar()
var2 = IntVar()
var3 = IntVar()
var4 = IntVar()
var5 = IntVar()

# Hexitize me captain
# (Not it use)
def hexitize(inputStr):

    # Convert string into its hex equivalent
    newStr = inputStr.encode("hex")

    return ' '.join(newStr[i:i+2] for i in xrange(0, len(newStr), 2))

#Print Code Caves
def printCaves():
	# Get the starting address of the program and the endding address
	beginning = idc.MinEA()
	end = idc.MaxEA()

	# Start the current address at the beginning of the program
	current = beginning
	
	i = 0
	
	# Iterate through the program finding code caves
	while current <= end:
		# Check if the disassembly at the line is empty
		if (idc.GetDisasm(current) == "db    0"):
			# Record the start of the cave
			startAddr = current
			# Variable to record the number of lines available in code cave
			size = 0
			# Iterate to the end of the code cave while checking that the edge
			# of the program has not been reached
			while (idc.GetDisasm(current) == "db    0"):
				# Increment the size of the cave by 1
				size = size + 1
				# Increment to the next address
				current = current + 1
			# Mark the end of the cave as the address at the end of the loop
			endAddr = current
			# Append the cave information to the list of caves
			print "Cave " + str(i) + ": "
			print "-------------------"
			print "Start: " + str(startAddr)
			print "End: " + str(endAddr)
			print "size: " + str(size)
			print "\n"
			i = i + 1
		# Go to the next address in the binary
		current = current + 1

# The patch-inator
def patchy_watchies(original, changed):
	hexStr = hexitize(changed)

	print "Hex: " + hexStr + "\n"
	print "Original: " + original + "\n"

	# Iterate through the segments of the binary
	for seg in idautils.Segments():
		# Segment name of the current segment
		segmentName = idc.SegName(seg)
		# Start address of the segment
		startAddr = idc.SegStart(seg)
		# Current address of the segment
		cur_addr = idc.SegStart(seg)
		# End address of the segment
		endAddr = idc.SegEnd(seg)
		# Check if the current segment is the segment for raw data
		if segmentName == ".rdata":
			# Iterate through the segment
			while cur_addr <= endAddr:
				# Check to see if the current address contains a String
				if type(idc.GetString(cur_addr)) == type("String"):
					# Check if the String contains the user request
					if idc.GetString(cur_addr).find(usrin) != -1:
						for i, c in enumerate(usrchange):
							print "patching byte"
							idc.PatchByte(cur_addr+i, int(c.encode("hex"), 16))
						break#for i, c in enumerate(str):
						#	idc.PatchByte(cur_addr+i, Byte(int(c, 16)))
						
					   # idc.PatchByte(cur_addr, ord(usrchange.encode("hex"), 16))
						
				# Move cursor to next head
				cur_addr = idc.NextHead(cur_addr, endAddr)           
	
#Run button command
def Run():
	#LEARN INFORMATION SELECTED
	if var.get() == 1:
		#NO ITEMS SELECTED TO FIND
		if var2.get() == 0:
			if var3.get() == 0:
				if var5.get() == 0:
					print "\nNothing to learn is selected."
					return
		#PRINT SEGEMENTS SELECTED
		if var2.get() == 1:
			print "\nSegments"
			print "-----------------------------"
			for seg in idautils.Segments():
				print idc.SegName(seg), idc.SegStart(seg), idc.SegEnd(seg)
		#PRINT FUNCTIONS SELECTED
		if var3.get() == 1:
			print "\nFunctions"
			print "-----------------------------"
			for func in idautils.Functions():
				print hex(func), idc.GetFunctionName(func)
		if var5.get() == 1:
			printCaves()
	#BYTE PATCHER SELECTED																																																																																																																																		
	elif var.get() == 2:
		#NO RADIO BUTTONS SELECTED, LEAVE
		if var4.get() == 0:
			print "\nNo patch functionality is selected."
			return
		#FIND STRING SELECTED
		if var4.get() == 20:
			print "\nYou Entered: " + E1.get()
			print "\nNot implemented yet."
		#PATCH BYTES SELECTED	
		elif var4.get() == 21:
			textField1 = E2.get()
			textField2 = E3.get()
			print "\nOriginal: " + textField1 + "\nNew: " + textField2
			
			if len(textField1) == 0:
				if len(textField2) == 0:
					print "Both fields are empty. Please input!"
					return
				else:
					print "Please input something to be patched!"
					return
			elif len(textField2) == 0:
				print "Please input something to patch!"
				return
				
			patchy_watchies(textField1, textField2)
	elif var.get() == 3:
		print "INJECTOR"
		print "You want to insert " + E4.get() + " at address " + E5.get()
		print "\nNot implemented yet."
	else:
		print "Nothing Selected!"


#LOGO
#------------------------------------------
#logo = PhotoImage(file="templogo.png")
#w1 = Label(root, image=logo).grid(row=0,column=0)


#TITLE BAR
#------------------------------------------
title = """MIP-BPI
Malicious IDAPro Byte-Patching Interface"""
titlebar = Label(root, text=title, justify=LEFT).grid(row=0,column=1,sticky=W)


#LEARN INFORMATION
#------------------------------------------
LI = Radiobutton(root, text = "LEARN INFROMATION", variable=var, value = 1).grid(row=1, column=0, sticky=W)
segs = Checkbutton(root, text = "Print Segments", variable=var2).grid(row=2, column=0,columnspan=1,sticky=E)
funcs = Checkbutton(root, text = "Print Functions", variable=var3).grid(row=3,column=0, columnspan=1,sticky=E)
caves = Checkbutton(root, text = "Print Code Caves", variable=var5).grid(row=4,column=0,columnspan=1,sticky=E)
#BYTE PATCHER SECTION
#------------------------------------------
BP = Radiobutton(root, text = "BYTE PATCHER", variable=var, value = 2).grid(row=5,column=0, sticky=W)

FS = Radiobutton(root, text = "FIND STRING", variable=var4, value = 20).grid(row=6,column=0,sticky=E)
E_1 = Label(root, text = "INPUT: ").grid(row=7,column=1,sticky=W)
E1 = Entry(root)
E1.grid(row=7,column=1,sticky=E)

PB = Radiobutton(root, text = "PATCH BYTES", variable=var4, value = 21).grid(row=8,column=0,sticky=E)
E_2 = Label(root, text = "OLD: ").grid(row=9,column=1,sticky=W)
E2 = Entry(root)
E2.grid(row=9,column=1,sticky=E)
E_3 = Label(root, text = "NEW: ").grid(row=10,column=1,sticky=W)
E3 = Entry(root)
E3.grid(row=10,column=1,sticky=E)

#INJECTOR SECTION
#------------------------------------------
I = Radiobutton(root, text = "INJECTOR", variable=var, value = 3).grid(row=11,column=0, sticky=W)
E_4 = Label(root, text = "ADDRESS: ").grid(row=12,column=1,sticky=W)
E4 = Entry(root)
E4.grid(row=12,column=1,sticky=E)
E_5 = Label(root, text = "ITEM: ").grid(row=13,column=1,sticky=W)
E5 = Entry(root)
E5.grid(row=13,column=1,sticky=E)

#RUN BUTTON
#------------------------------------------
RUN = Button(root, text = "RUN", command = lambda : Run()).grid(row=14,column=0, sticky=E)


#QUIT BUTTON
#-----------------------------------------
QUIT = Button(root, text = "QUIT", command = root.quit).grid(row=14,column=1, sticky=W)


root.mainloop()
root.destroy()