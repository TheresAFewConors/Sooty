import random

def titleOpen():
    var = random.randint(1,2)
    if var == 1:
        print('''                                           
 @@@@@@    @@@@@@    @@@@@@   @@@@@@@  @@@ @@@  
@@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@  @@@ @@@  
!@@       @@!  @@@  @@!  @@@    @@!    @@! !@@  
!@!       !@!  @!@  !@!  @!@    !@!    !@! @!!  
!!@@!!    @!@  !@!  @!@  !@!    @!!     !@!@!   
 !!@!!!   !@!  !!!  !@!  !!!    !!!      @!!!   
     !:!  !!:  !!!  !!:  !!!    !!:      !!:    
    !:!   :!:  !:!  :!:  !:!    :!:      :!:    
:::: ::   ::::: ::  ::::: ::     ::       ::    
:: : :     : :  :    : :  :      :        :    
 
                           by @TheresAFewConors''')
    if var == 2:
        print('''

   _____             _         
  / ____|           | |        
 | (___   ___   ___ | |_ _   _ 
  \___ \ / _ \ / _ \| __| | | |
  ____) | (_) | (_) | |_| |_| |
 |_____/ \___/ \___/ \__|\__, |
                          __/ |
                         |___/ 
                         
                            by @TheresAFewConors
''')
    print("\n The SOC Analyst's all-in-one tool to "
          "automate and speed up workflow ")
    input('\n Press Enter to continue..')
