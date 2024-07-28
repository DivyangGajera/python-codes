import tkinter as tk

# creating the main window named 'master' using tkinter constructor
master = tk.Tk()

# define window size and title
master.geometry('600x400')
master.title('BNS - UP by Divyang')

#global variables
capture = 0
button_lable = tk.StringVar() 
listOfPacketsSniffed = []


# afunctiom that will change the main varible that'll stop the sniffer and also change the lable of the button
def change_sign():
    global capture
    global button_lable
    if capture == 1:
        capture = 0
        # button_lable.set('Stop Capturing')
        button0.config(text='Start Capturing')
        print('stoped capturing')
    elif capture == 0:
        capture = 1
        # button_lable.set('Start Capturing')
        button0.config(text='Stop Capturing')
        print('started capturing')

    print(bool(capture))
    # print(button_lable)

# defining buttons and labels and other usefull widgets
text1 = tk.Label(master,text='Basic Network Sniffer', font=('Times New Roman',25))
button0 = tk.Button(master, text= 'Start Capturing',font=('Ariel Bold',20), command=change_sign)
show_data = tk.Label(master,text="\n".join(listOfPacketsSniffed), font=('Ariel',15)) 


# packing things in a linear layout
text1.pack()
button0.pack()

# calling the main window to show the window
master.mainloop()


