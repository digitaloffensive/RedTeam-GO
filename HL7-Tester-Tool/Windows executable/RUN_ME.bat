@echo off
title HL7 Security Tester
color 0A
echo.
echo  HL7 Security Tester - Quick Start Examples
echo  ============================================
echo.
echo  STEP 1 - Probe the receiver (run this first)
echo  -----------------------------------------------
echo  hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -probe
echo.
echo  STEP 2 - Run all security tests
echo  ----------------------------------
echo  hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file sample_messages.hl7
echo.
echo  STEP 3 - Save a JSON report
echo  -----------------------------
echo  hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file sample_messages.hl7 -output json -out-file report.json
echo.
echo  CAPTURED MESSAGE (ventilator/patient monitor)
echo  -----------------------------------------------
echo  hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls-auto -file captured_vitals.hl7 -sanitize -no-response
echo.
echo  FUZZER
echo  --------
echo  hl7-security-tester.exe -fuzz captured_vitals.hl7 -host 10.0.0.5 -port 2575 -tls-auto -fuzz-sending-app HL7SECTEST -fuzz-delay 0 -fuzz-iter 500 -fuzz-out results.csv
echo.
echo  HELP
echo  ------
echo  hl7-security-tester.exe --help
echo.
echo  Edit the commands above to match your target host and port.
echo  See README.md for the full flag reference.
echo.
pause
