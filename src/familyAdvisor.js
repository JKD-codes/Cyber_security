// Rule-based Family Safety Advisor.
// Reads the incident description, detects which known scam pattern(s) it matches,
// and builds advice tailored to the persona (Elder / Adult / Teen).
// It never invents a scam type: if nothing matches, it says so and gives general guidance.

const H = {
  cyber: { name: 'National Cyber Crime Helpline', number: '1930' },
  portal: { name: 'Report online: Cyber Crime Portal', number: 'cybercrime.gov.in' },
  chakshu: { name: 'Report fraud call/SMS: Sanchar Saathi (Chakshu)', number: 'sancharsaathi.gov.in' },
  elder: { name: 'Elderline (Senior Citizens)', number: '14567' },
  child: { name: 'Childline', number: '1098' },
  women: { name: 'Women Helpline', number: '181' },
  sachet: { name: 'Report illegal loan / deposit apps: RBI Sachet', number: 'sachet.rbi.org.in' },
  stopncii: { name: 'Stop intimate images spreading', number: 'stopncii.org' },
  police: { name: 'Police Emergency', number: '112' },
};

// Each pattern: [regex, weight, warning-sign explanation shown when it matches]
const CATEGORIES = [
  {
    id: 'digital_arrest',
    threatType: '"Digital Arrest" / Fake Police or CBI Scam',
    level: 'Critical', police: true, helplines: [H.cyber, H.police, H.chakshu],
    patterns: [
      [/digital(ly)? arrest/, 6, 'Police never do a "digital arrest". There is no such thing in Indian law.'],
      [/\b(cbi|police|ncb|narcotics|customs|ed officer|enforcement directorate|crime branch|cyber cell|trai|rbi officer|income tax officer)\b/, 3, 'The caller claimed to be from police / CBI / customs / a regulator to frighten you.'],
      [/\b(arrest|warrant|fir|case (is )?(registered|filed)|money laundering|illegal (parcel|items|activit(y|ies)))\b/, 3, 'They threatened arrest or a legal case. Real agencies send written notices, they do not threaten on calls.'],
      [/(parcel|package|courier).{0,40}(drugs|passports?|mdma|illegal)|(drugs|passports?).{0,40}(parcel|package|courier)/, 4, 'The "parcel with drugs/passports in your name" story is a script used by organised gangs.'],
      [/(video call|skype|whatsapp call).{0,60}(police|officer|uniform|cbi|court)|(police|officer|uniform|cbi|court).{0,60}(video call|skype)/, 4, 'Officials do not interrogate people over Skype/WhatsApp video calls.'],
      [/(aadhaar|aadhar|sim|phone number).{0,40}(misused|used in|linked to).{0,30}(crime|case|laundering|illegal)/, 3, 'They claimed your Aadhaar/SIM was used in a crime, to make you panic.'],
      [/(don'?t|do not|not to) (tell|inform) (anyone|family|anybody)|stay on (the )?(call|camera)/, 3, 'They told you to stay on the call and not tell family. That is to isolate you.'],
      [/(verify|verification|safe|rbi) account|transfer.{0,30}(for verification|to clear)/, 3, 'They asked you to move money to a "safe/verification account". No agency does this.'],
    ],
    summary: 'This is a "digital arrest" scam. Criminals pretend to be police, CBI or customs officers and frighten you into paying. Real police never arrest anyone over a video call and never ask for money to "clear your name".',
    steps: [
      'Disconnect the call now. You do not have to stay on camera, and you are not under arrest.',
      'Do NOT transfer any money to "verify" or "clear" your account.',
      'Tell a family member right away. The scammers want you to keep it secret.',
      'Call 1930 or file a complaint at cybercrime.gov.in. Report the number on Sanchar Saathi (Chakshu).',
    ],
  },
  {
    id: 'sextortion',
    threatType: 'Sextortion / Video-Call Blackmail',
    level: 'Critical', police: true, helplines: [H.cyber, H.stopncii, H.women],
    patterns: [
      [/(nude|naked|obscene|explicit|intimate|private) (video|photo|pic|image|call)|video call.{0,40}(nude|naked|obscene|girl|woman|undress)/, 5, 'A stranger\'s video call with nudity is a set-up: they screen-record your face to blackmail you.'],
      [/(blackmail|threaten(ing|ed)? to (leak|share|post|send|viral)|make (it )?viral|send (it )?to (my |your )?(family|friends|contacts))/, 5, 'They are threatening to share a video or photo unless you pay. This is a crime called sextortion.'],
      [/morph(ed)?|edited (photo|pic|image)|deepfake/, 4, 'They use morphed/AI-edited images. These can be taken down and reported.'],
      [/recorded (me|my|the call|video)/, 3, 'They claim to have recorded you, to put pressure on you.'],
    ],
    summary: 'This is sextortion. Criminals record or fake an intimate video and threaten to share it unless you pay. Paying never stops them. They just ask for more. You are the victim here, and help is available.',
    steps: [
      'Do NOT pay anything. Payment always leads to more demands.',
      'Stop replying. Block the person, but first take screenshots of the chats, their profile and payment requests as evidence.',
      'Report at cybercrime.gov.in (there is a special category for this) or call 1930.',
      'If an intimate image is involved, use StopNCII.org to stop it being shared on major platforms.',
      'Report the profile on the app (Instagram/WhatsApp/Facebook). They remove such accounts quickly.',
    ],
    support: 'This is not your fault and you are not alone. These gangs target thousands of people and rarely carry out their threats once you stop responding.',
  },
  {
    id: 'remote_access',
    threatType: 'Remote-Access / Screen-Sharing App Scam',
    level: 'Critical', police: true, helplines: [H.cyber, H.portal],
    patterns: [
      [/\b(anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|airdroid|screen ?shar(e|ing)|remote (access|app))\b/, 6, 'They asked you to install a screen-sharing app. This lets them see your OTPs and control your phone.'],
      [/\.apk\b|\bapk (file|app)?\b|install (this|the|an?) (app|application|file)|download (this|the|an?) (app|application|file)/, 4, 'They sent an app/APK file to install. Fake APKs steal SMS, OTPs and banking passwords.'],
    ],
    summary: 'Someone is trying to get control of your phone or computer. Screen-sharing apps and unknown APK files let scammers watch your screen, read your OTPs and empty your bank account.',
    steps: [
      'Do NOT install the app. If you already did, uninstall it and switch on Airplane mode immediately.',
      'If you installed an APK, call your bank to block net-banking/UPI, then reset the phone or get it checked.',
      'Change your banking, UPI and email passwords from a different, safe device.',
      'Report the incident on 1930.',
    ],
  },
  {
    id: 'sim_forwarding',
    threatType: 'Call-Forwarding / SIM-Swap Hijack',
    level: 'Critical', police: true, helplines: [H.cyber, H.chakshu],
    patterns: [
      [/\*\s?40[1-9]\s?\*|\*\*?2[12]\*|\*\*6[12]\*|##002#|dial.{0,20}(\*|#)\d/, 6, 'They asked you to dial a code starting with * or #. This forwards your calls (and OTP calls) to the scammer.'],
      [/sim (card )?(swap|upgrade|replace|block|will be (blocked|deactivated))|5g (upgrade|sim)|esim (activation|upgrade|conversion)/, 4, 'Fake "SIM upgrade / eSIM" calls are used to take over your phone number.'],
      [/(network|signal) (gone|lost|stopped)|no network.{0,30}(suddenly|since)/, 2, 'Sudden loss of mobile network can mean your SIM has been swapped.'],
    ],
    summary: 'This is a call-forwarding or SIM-swap attack. Scammers take over your phone number to receive your bank OTPs and WhatsApp codes.',
    steps: [
      'Do NOT dial any code they gave you. If you did, dial ##002# right away to cancel all call forwarding.',
      'If your mobile network suddenly disappeared, visit your mobile operator store with ID immediately.',
      'Call your bank to temporarily block transactions until your number is safe.',
      'Turn on WhatsApp two-step verification (Settings → Account → Two-step verification).',
    ],
  },
  {
    id: 'qr_upi',
    threatType: 'QR Code / UPI "Receive Money" Scam',
    level: 'Critical', police: false, helplines: [H.cyber, H.portal],
    patterns: [
      [/(scan|send).{0,30}qr|qr.{0,30}(scan|code|to receive|to get)/, 4, 'Scanning a QR code is ONLY used to pay money, never to receive it.'],
      [/(enter|put|type).{0,20}(upi )?pin.{0,30}(receive|get|credit|refund)|(receive|get|credit|refund).{0,30}(enter|put|type).{0,20}pin/, 6, 'You are being asked to enter your UPI PIN to "receive" money. Entering your PIN always sends money.'],
      [/collect request|payment request|request money|request (of|for) (rs|₹)/, 4, 'A UPI "collect/payment request" takes money from you when you approve it.'],
      [/\b(olx|quikr|marketplace|facebook market)\b/, 2, 'Online selling platforms (OLX, Marketplace) are where these fake buyers operate.'],
      [/\b(army|military|crpf|bsf|jawan|soldier|cisf)\b/, 3, 'Scammers often claim to be army/CRPF personnel to earn instant trust.'],
      [/(advance|refund|payment).{0,30}(via|on|through) (gpay|google pay|phonepe|paytm|upi)|(gpay|google pay|phonepe|paytm|upi).{0,40}(advance|refund)/, 2, 'They insist on sending an "advance" or "refund" by UPI in an unusual way.'],
      [/(sent|paid) (more|extra|excess)|(mistakenly|wrongly|by mistake) (sent|transferred)|(sent|transferred|credited).{0,30}(by mistake|mistakenly|wrongly|accidentally)/, 4, '"I sent you extra money by mistake, please return it" is a classic refund trick.'],
      [/(return|send back|refund) (it|the money|the amount)|(don'?t|do not|cannot|can'?t) see (it|the money) in (my )?(bank|account)/, 2, 'They want money "returned", but the money never actually reached your bank account. Their screenshot is fake.'],
    ],
    summary: 'This is a UPI / QR code scam. To RECEIVE money you never need to scan a QR code, approve a request or enter your UPI PIN. Doing any of these sends money FROM your account.',
    steps: [
      'Do not scan any QR code or approve any UPI request from this person.',
      'Remember: entering your UPI PIN = paying money. You never enter a PIN to receive money.',
      'If someone says they "sent extra by mistake", check your actual bank balance in your bank app, not their screenshot.',
      'Block and report the person on the platform (OLX/WhatsApp) and on 1930 if money was lost.',
    ],
  },
  {
    id: 'bank_otp',
    threatType: 'Bank / OTP / Card Fraud Call',
    level: 'Critical', police: false, helplines: [H.cyber, H.chakshu],
    patterns: [
      [/(share|tell|give|send|provide|read out|asked (for|me)).{0,40}\b(otp|cvv|pin|password|card (number|details))\b|\b(otp|cvv|pin)\b.{0,40}(share|tell|give|send|asked|provide)/, 6, 'They asked for your OTP / CVV / PIN. Banks NEVER ask for these, not even their own staff.'],
      [/(bank|sbi|hdfc|icici|axis|kotak|pnb|bank of baroda|canara|rbi).{0,40}(manager|officer|official|executive|staff|customer care|calling|called)/, 3, 'The caller said they were from your bank. Anyone can claim this.'],
      [/(card|account|debit card|credit card|net ?banking).{0,30}(block|blocked|suspend|frozen|freeze|deactivat|expir|close)/, 3, 'They threatened that your card or account will be blocked, to rush you.'],
      [/(reward points?|credit limit|card upgrade|cashback).{0,40}(redeem|increase|upgrade|expire|expiring)/, 3, '"Reward points expiring / credit limit increase" calls are a common bait.'],
      [/\botp\b/, 1, 'An OTP is involved. An OTP should only ever be typed by you on your own screen.'],
    ],
    summary: 'This is a bank fraud attempt. Scammers pretend to be bank staff to get your OTP, CVV, card number or PIN. No real bank employee will ever ask for these.',
    steps: [
      'Do not share any OTP, CVV, PIN or card number. Hang up.',
      'Call your bank only on the number printed on the back of your card or in the official app.',
      'If you already shared details, block your card in the bank app immediately and call 1930.',
      'Report the caller\'s number on Sanchar Saathi (Chakshu).',
    ],
  },
  {
    id: 'kyc',
    threatType: 'Fake KYC / PAN / Aadhaar Update Scam',
    level: 'High', police: false, helplines: [H.cyber, H.chakshu],
    patterns: [
      [/\bkyc\b/, 4, 'KYC update requests by SMS/call with a link are almost always fake. Banks ask you to visit the branch or use the official app.'],
      [/(pan|aadhaar|aadhar)( card)?.{0,30}(update|link|expired|expire|verify|block)/, 4, 'They said your PAN/Aadhaar needs updating, to make you click a link.'],
      [/(update|verify).{0,20}(details|account).{0,40}(link|click|today|immediately|24 hours)/, 3, 'A deadline with a link ("update today or account blocked") is a phishing pattern.'],
    ],
    summary: 'This is a fake KYC update message. Scammers send links that look like your bank to steal your login, card details and OTP.',
    steps: [
      'Do not click the link or call the number in the message.',
      'If KYC is really pending, your bank\'s official app or branch will show it.',
      'If you entered details on the link, change your net-banking password and call your bank now.',
      'Report the SMS on Sanchar Saathi (Chakshu) and delete it.',
    ],
  },
  {
    id: 'electricity',
    threatType: 'Electricity Bill Disconnection Scam',
    level: 'High', police: false, helplines: [H.cyber, H.chakshu],
    required: [0, 1], // needs BOTH electricity context and a disconnection/overdue threat
    patterns: [
      [/electricity|power (supply|connection|cut)|light (will be|cut)|bijli|\bmseb\b|\bbescom\b|\btneb\b|discom/, 4, 'They claimed to be from the electricity department.'],
      [/(bill|connection).{0,40}(not updated|pending|overdue|unpaid|disconnect|cut)|disconnect.{0,30}(tonight|today|\d+ ?(min|minutes|hours?))/, 4, 'They threatened disconnection within minutes/hours. Real electricity boards give written notice days in advance.'],
      [/(call|contact).{0,20}(this|the|our) (number|officer)|\b[6-9]\d{9}\b/, 2, 'The message came from, or asks you to call, a personal 10-digit mobile number, not an official board helpline.'],
    ],
    summary: 'This is a fake electricity bill scam. Your power will not be cut tonight. Scammers create panic so you call them, install an app, or pay through their link.',
    steps: [
      'Do not call the number in the message and do not install any app they suggest.',
      'Check your bill only on your electricity board\'s official website/app or at the local office.',
      'Never pay through a link sent by SMS/WhatsApp.',
      'Report the SMS on Sanchar Saathi (Chakshu).',
    ],
  },
  {
    id: 'job_task',
    threatType: 'Part-Time Job / "Task" Scam',
    level: 'High', police: false, helplines: [H.cyber, H.portal],
    patterns: [
      [/(like|subscribe|rate|review).{0,30}(videos?|youtube|hotels?|products?|google maps|restaurants?)/, 5, 'Being paid to like videos or rate hotels is a known task-scam script.'],
      [/(part[- ]?time|work from home|home based|online) (job|work|income|earning)/, 3, 'An unexpected part-time / work-from-home offer from a stranger.'],
      [/earn.{0,25}(rs\.?|₹|inr)?\s?\d[\d,]*.{0,20}(daily|per day|a day|per task|weekly)/, 4, 'Promises of large daily earnings for very little work.'],
      [/\btelegram\b/, 3, 'They moved you to a Telegram group. Scam operations run from Telegram to avoid being traced.'],
      [/(prepaid|vip|merchant|premium) task|deposit.{0,30}(task|unlock|withdraw)|(pay|deposit|invest).{0,30}(to )?(withdraw|unlock|release)/, 5, 'They ask you to deposit money to "unlock" tasks or withdraw earnings. That is how they take your money.'],
      [/(\+|00)(62|84|855|60|92|63|880)\b|international number/, 3, 'The message came from a foreign number (e.g. +62, +84, +855). These jobs are run from overseas scam centres.'],
    ],
    summary: 'This is a task-based job scam. They pay a small amount first to win your trust, then ask you to deposit larger sums to "unlock" tasks or withdraw, and that money is never returned.',
    steps: [
      'Stop doing tasks and do not deposit any more money, even if they say you will lose your "earnings".',
      'Exit the Telegram/WhatsApp group and block the recruiters.',
      'If you have paid, report on 1930 / cybercrime.gov.in quickly with the UPI IDs and transaction IDs.',
      'Do not share your Aadhaar/PAN or bank details with them.',
    ],
  },
  {
    id: 'investment',
    threatType: 'Fake Investment / Trading / Crypto Scam',
    level: 'Critical', police: false, helplines: [H.cyber, H.portal, H.sachet],
    patterns: [
      [/(guaranteed|assured|fixed|high|double|triple|\d+ ?%).{0,30}(returns?|profit|income)|double (your|the) money/, 5, 'Guaranteed or very high returns are impossible in real investing.'],
      [/(stock|share|trading|ipo|forex|crypto|bitcoin|usdt|f&o).{0,40}(tips|group|app|platform|account|allotment|mentor|expert|advisor)/, 4, 'Stock-tip/trading groups led by "experts" on WhatsApp or Telegram are a major fraud channel.'],
      [/institutional account|(otc|vip) (account|trading)|withdraw.{0,30}(tax|fee|charge|blocked)/, 5, 'They ask for "tax/fees" before you can withdraw. Real platforms deduct charges, they never ask you to pay to withdraw.'],
      [/(whatsapp|telegram) group/, 2, 'Investment advice is coming from a WhatsApp/Telegram group, not a SEBI-registered advisor.'],
    ],
    summary: 'This looks like an investment / trading scam. Fake apps show big profits on screen, but the money is never real and withdrawals get blocked with new "fees".',
    steps: [
      'Do not invest any more money and do not pay any "tax" or "fee" to withdraw.',
      'Only use SEBI-registered brokers and check advisors on sebi.gov.in.',
      'Take screenshots of the group, app and payments, then report on 1930 / cybercrime.gov.in.',
      'Leave the group and block the "mentor".',
    ],
  },
  {
    id: 'lottery',
    threatType: 'Lottery / Prize / KBC Scam',
    level: 'High', police: false, helplines: [H.cyber, H.chakshu],
    required: [0], // must actually mention winning; a "fee" alone is not a lottery scam
    patterns: [
      [/lottery|jackpot|lucky draw|\bkbc\b|kaun banega|won (a |the )?(prize|car|cash|lottery|rs|₹|\d)|you (have )?won|winner/, 5, 'You "won" a lottery or prize you never entered.'],
      [/(processing|registration|gst|tax|delivery|clearance|transfer) (fee|charge)|pay.{0,30}(to (claim|receive|release))/, 5, 'They want a fee before releasing the prize. Real prizes never require payment.'],
      [/(gift|prize|car|cash).{0,30}(claim|collect|release)/, 2, 'They pressure you to claim the prize quickly.'],
    ],
    summary: 'This is a lottery / prize scam. You cannot win a lottery you never entered, and genuine prizes never ask you to pay a fee or tax first.',
    steps: [
      'Do not pay any fee, tax or charge.',
      'Do not share your bank details, Aadhaar or PAN.',
      'Block the number and report it on Sanchar Saathi (Chakshu).',
    ],
  },
  {
    id: 'courier',
    threatType: 'Fake Courier / Parcel Delivery Scam',
    level: 'High', police: false, helplines: [H.cyber, H.chakshu],
    patterns: [
      [/(parcel|package|courier|shipment|delivery).{0,40}(held|stuck|pending|failed|on hold|returned|address|reschedul|customs)/, 4, 'A message says your parcel is held or the address is incomplete.'],
      [/(india post|fedex|dhl|blue ?dart|delhivery|dtdc|ekart)/, 2, 'They use the name of a courier company to look genuine.'],
      [/(small|re-?delivery|customs|address update) (fee|charge)|pay (rs\.?|₹)\s?\d{1,3}\b/, 4, 'They ask for a small fee (₹5–₹50). The real goal is your card details.'],
    ],
    summary: 'This is a fake courier/parcel message. It tries to get you to click a link and pay a tiny fee, which steals your card or UPI details.',
    steps: [
      'Do not click the link or pay any fee.',
      'Track parcels only in the official app/website of the shop or courier using the tracking number you already have.',
      'Report and delete the message.',
    ],
  },
  {
    id: 'loan_app',
    threatType: 'Illegal Instant Loan App Harassment',
    level: 'High', police: true, helplines: [H.cyber, H.sachet, H.portal],
    patterns: [
      [/(instant|quick|easy|pre-?approved) loan|loan app|loan without (documents|cibil)/, 4, 'Instant loan apps outside RBI-regulated lenders are often illegal.'],
      [/(recovery|loan) agents?.{0,40}(threat|abus|harass|call)|harass(ing|ment)?.{0,40}(loan|repay)/, 5, 'Abusive recovery calls are illegal under RBI rules.'],
      [/(contacts|contact list|gallery|photos).{0,40}(access|send|message|share)|messag(e|ing) my (contacts|friends|family)/, 4, 'They accessed your contacts/photos to shame you. That is a crime.'],
      [/(processing fee|upfront fee).{0,30}loan|loan.{0,30}(processing fee|upfront fee)/, 4, 'Asking for a fee before giving a loan is an advance-fee fraud.'],
    ],
    summary: 'This looks like an illegal loan-app scam. These apps charge huge hidden fees and then harass you and your contacts. Their actions are illegal and you can report them.',
    steps: [
      'Do not pay any more money under threat. Keep records of all payments and calls.',
      'Uninstall the app and remove its permissions (contacts, photos, SMS).',
      'Report on cybercrime.gov.in / 1930 and on RBI Sachet (sachet.rbi.org.in). Tell friends to ignore any messages from them.',
      'If morphed photos are circulated, file a police complaint. This is a serious offence.',
    ],
  },
  {
    id: 'relative_impersonation',
    threatType: 'Fake Relative / Friend Emergency (incl. AI Voice Clone)',
    level: 'High', police: false, helplines: [H.cyber, H.police],
    patterns: [
      [/(new number|changed (my )?number|lost (my )?phone).{0,60}(mum|mom|mummy|dad|papa|son|daughter|bhai|beta|friend)|(hi|hello) (mum|mom|mummy|dad|papa)/, 5, '"New number, this is your son/daughter" messages are a known impersonation trick.'],
      [/(son|daughter|grandson|granddaughter|nephew|relative|friend|brother|sister|husband|wife).{0,60}(accident|hospital|arrested|police station|stuck|in trouble|emergency)/, 5, 'An emergency story about a family member is used to make you pay without thinking.'],
      [/(voice|sounded) (like|exactly like|same as)|ai voice|crying (on|over) the (phone|call)/, 4, 'Scammers now clone voices with AI from short social-media clips.'],
      [/(urgent(ly)?|immediately).{0,30}(need|send|transfer).{0,20}(money|rs|₹|\d)/, 3, 'An urgent request for money with no time to check.'],
    ],
    summary: 'This may be someone impersonating your family member or friend, sometimes even with an AI-cloned voice. They invent an emergency so you pay before checking.',
    steps: [
      'Do not send money yet. Hang up and call the person on their OLD, known number.',
      'Ask a question only the real person would know, or agree a family "code word".',
      'Contact another family member to confirm the story.',
      'If it was fake, report the number on 1930.',
    ],
  },
  {
    id: 'romance',
    threatType: 'Romance / Matrimonial / Gift Parcel Scam',
    level: 'High', police: false, helplines: [H.cyber, H.women],
    patterns: [
      [/(met|know|known|chatting).{0,40}(online|instagram|facebook|dating|tinder|bumble|matrimon|shaadi|jeevansathi)/, 3, 'The relationship started online and you have not met in person.'],
      [/(never met|not met|haven'?t met)/, 3, 'You have never met this person face-to-face.'],
      [/(gift|parcel).{0,60}(customs|airport|stuck|clearance)/, 5, 'A foreign "gift parcel stuck at customs" is a classic romance-scam follow-up.'],
      [/(abroad|foreign|uk|usa|london|dubai|doctor|engineer|army officer).{0,60}(send|transfer|need).{0,20}money/, 4, 'An overseas partner suddenly needing money.'],
    ],
    summary: 'This has the signs of a romance or matrimonial scam. The person builds trust online, then invents a problem (customs, medical, visa) that needs money.',
    steps: [
      'Do not send money or pay "customs" for any gift.',
      'Do a reverse image search of their photos (Google Lens). Scammers use stolen pictures.',
      'Talk to a friend or family member about the relationship.',
      'Report the profile on the platform and on 1930 if you paid.',
    ],
  },
  {
    id: 'fake_support',
    threatType: 'Fake Customer Care / Refund Scam',
    level: 'High', police: false, helplines: [H.cyber, H.portal],
    patterns: [
      [/customer (care|support|service)( number)?.{0,40}(google|search|online|found)|(google|search(ed)?).{0,40}customer (care|support)/, 5, 'Customer-care numbers found on Google search results are often planted by scammers.'],
      [/refund.{0,40}(process|initiate|get|claim|form|link)|(cancel|cancelled|failed) (order|transaction|booking).{0,40}refund/, 3, 'They promised to "process a refund" which needs your details or an app.'],
      [/(fill|submit).{0,20}(form|link).{0,30}(refund|complaint)|(refund|complaint).{0,30}(form|link)/, 3, 'A refund "form" link is used to collect card/UPI details.'],
    ],
    summary: 'This looks like a fake customer-care scam. Scammers post fake helpline numbers online and then "help" with a refund by stealing your banking details.',
    steps: [
      'Only use customer-care numbers from the official app or website of the company.',
      'Never install apps, fill "refund forms" or share OTP for a refund. Refunds come back automatically.',
      'If money was taken, call your bank and 1930 immediately.',
    ],
  },
  {
    id: 'phishing_link',
    threatType: 'Phishing Link / Fake SMS',
    level: 'High', police: false, helplines: [H.cyber, H.chakshu],
    patterns: [
      [/(click|open|tap).{0,20}(the |a |this )?link|https?:\/\/|www\.|bit\.ly|\.(xyz|top|tk|cc|link|click|in)\b/, 3, 'The message pushes you to open a link. Fake sites copy the look of real banks/government sites.'],
      [/(traffic )?challan|e-?challan|income tax refund|fastag|gas (connection|subsidy)|pm kisan|subsidy/, 3, 'Fake challan / tax refund / subsidy messages are common phishing lures.'],
      [/(within|in) (24|48) hours|today only|last (date|chance|warning)|immediately/, 2, 'An urgent deadline is used to stop you thinking.'],
    ],
    summary: 'This message is likely a phishing attempt. The link leads to a fake website that steals passwords, card numbers or OTPs.',
    steps: [
      'Do not open the link. If you opened it, do not enter any details.',
      'Paste the link into the Scam Detector tab of this app to check it.',
      'Reach the organisation by typing its official website yourself or using its app.',
      'Report the message on Sanchar Saathi (Chakshu).',
    ],
  },
];

const PERSONA = {
  Elder: {
    step: 'Before doing anything with money, call a trusted family member and tell them what happened.',
    support: 'Take a slow breath. You did the right thing by checking first. Scammers rely on panic, and you have stopped it.',
    helplines: [H.elder],
    unclear: 'Please ask a younger family member to look at the message or call with you.',
  },
  Adult: {
    step: 'Warn your family (especially elderly parents and teenagers) about this scam. They are often targeted next.',
    support: 'Stay calm. Cut off contact first, then report. Quick reporting gives the best chance of recovering money.',
    helplines: [],
    unclear: 'When in doubt, do not pay and verify through official channels you find yourself.',
  },
  Teen: {
    step: 'Tell a parent, older sibling or trusted adult. You are not in trouble, and they can help you sort this out.',
    support: 'You were smart to check this. Scammers target young people on Instagram, Telegram and gaming apps every day.',
    helplines: [H.child],
    unclear: 'Show the message to a parent or trusted adult before replying.',
  },
};

// Did the user / their family member ALREADY lose money or hand over details? (affirmative statements only)
const WHO = '(i|we|my (father|mother|dad|mom|mum|son|daughter|husband|wife|grandfather|grandmother|parents)|(he|she|father|mother|dad|mom|papa|mummy|grandpa|grandma))';
const VICTIM_RE = new RegExp(
  `\\b${WHO} (have |has |had |already |just |then |also )*(paid|transferred|lost (rs|money|\\d)|sent (him|her|them|the money|money|rs|\\d)|` +
  `(shared|gave|told (him|her|them)|entered|typed) (my |his |her |the |our )?(otp|upi pin|pin|cvv|card|password|bank details|details)|installed (it|the|that|anydesk|teamviewer|the app)|scanned (it|the qr|the code))` +
  `|money (was |got |has been )?(deducted|debited|taken|gone|stolen)|lost (rs\\.?|inr)?\\s?\\d|amount (was |got )?debited|already (paid|transferred)`
);

function normalise(text) {
  return ` ${(text || '').toLowerCase().replace(/₹/g, ' rs ').replace(/\s+/g, ' ')} `;
}

export function detectScamCategories(text) {
  const t = normalise(text);
  const results = [];
  for (const cat of CATEGORIES) {
    let score = 0;
    const signs = [];
    const hit = new Set();
    cat.patterns.forEach(([re, w, sign], i) => {
      if (re.test(t)) {
        score += w;
        signs.push(sign);
        hit.add(i);
      }
    });
    if (score >= 4 && (cat.required || []).every((i) => hit.has(i))) results.push({ cat, score, signs });
  }
  results.sort((a, b) => b.score - a.score);
  return results;
}

const LEVEL_ORDER = ['Low', 'Medium', 'High', 'Critical'];
const maxLevel = (a, b) => (LEVEL_ORDER.indexOf(a) >= LEVEL_ORDER.indexOf(b) ? a : b);

function uniqueBy(arr, key) {
  const seen = new Set();
  return arr.filter((x) => {
    const k = key(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function buildFamilyAdvice(description, persona = 'Adult') {
  const p = PERSONA[persona] || PERSONA.Adult;
  const t = normalise(description);
  const matches = detectScamCategories(description);
  const isVictim = VICTIM_RE.test(t); // affirmative only: "I did not pay" does not match

  if (!matches.length) {
    // Nothing recognised: be honest, give general guidance
    const genericRisk = /(money|pay|rs |otp|pin|link|bank|upi|transfer|urgent|unknown number|stranger)/.test(t);
    return {
      threatLevel: isVictim ? 'High' : genericRisk ? 'Medium' : 'Low',
      threatType: 'No known scam pattern recognised',
      alreadyAffected: isVictim,
      detectedTypes: [],
      confidence: 'low',
      simpleSummary: isVictim
        ? 'We could not match this to a specific known scam, but since money or details may already have been shared, act quickly to protect your accounts.'
        : 'We could not match this to any known scam pattern. That does not guarantee it is safe. Add more details (what they asked for, how they contacted you) for a better check.',
      whatToDoNow: uniqueBy([
        ...(isVictim ? ['Call 1930 right away and contact your bank to block further transactions.'] : []),
        'Do not share OTPs, PINs, passwords or card details with anyone.',
        'Do not send money or install apps because someone asked you to over a call or message.',
        'Verify by contacting the organisation or person through a number you find yourself.',
        p.unclear,
      ], (s) => s),
      warningSignsExplained: genericRisk
        ? ['The situation involves money, banking details or a link from someone you cannot verify. Treat it with caution.']
        : ['No warning signs found in the description provided.'],
      shouldCallPolice: isVictim,
      emotionalSupport: p.support,
      helplines: uniqueBy([H.cyber, ...p.helplines], (h) => h.number),
    };
  }

  const top = matches[0];
  const secondary = matches.slice(1, 3).filter((m) => m.score >= 5);
  let level = top.cat.level;
  secondary.forEach((m) => { level = maxLevel(level, m.cat.level); });
  if (isVictim) level = 'Critical';

  const victimSteps = isVictim
    ? [
        'URGENT: Call 1930 now. Reporting within the first hour gives the best chance of freezing the stolen money.',
        'Call your bank\'s official helpline to block your card/UPI/net-banking and dispute the transaction.',
        'Save screenshots of chats, call logs, UPI/transaction IDs. You will need them for the complaint.',
      ]
    : [];

  const steps = uniqueBy([
    ...victimSteps,
    ...top.cat.steps,
    ...secondary.flatMap((m) => m.cat.steps.slice(0, 2)),
    p.step,
  ], (s) => s);

  const signs = uniqueBy([...top.signs, ...secondary.flatMap((m) => m.signs)], (s) => s);
  const typeLabel = [top.cat.threatType, ...secondary.map((m) => m.cat.threatType)].join(' + ');
  const confidence = top.score >= 9 ? 'high' : top.score >= 6 ? 'medium' : 'low';

  let summary = top.cat.summary;
  if (secondary.length) summary += ` It also shows signs of: ${secondary.map((m) => m.cat.threatType).join(', ')}.`;
  if (isVictim) summary = 'It sounds like money or details may already have been shared, so act right now. ' + summary;

  return {
    threatLevel: level,
    threatType: typeLabel,
    alreadyAffected: isVictim,
    detectedTypes: [top, ...secondary].map((m) => m.cat.id),
    confidence,
    simpleSummary: summary,
    whatToDoNow: steps,
    warningSignsExplained: signs,
    shouldCallPolice: isVictim || top.cat.police || secondary.some((m) => m.cat.police),
    emotionalSupport: top.cat.support ? `${top.cat.support} ${p.support}` : p.support,
    helplines: uniqueBy([...top.cat.helplines, ...secondary.flatMap((m) => m.cat.helplines), ...p.helplines], (h) => h.number),
  };
}
