---
title: After Setting a SIM PIN and Hiding Lock Screen Notifications, Are You Safe?
date: 2020-09-11 10:56:27
tags: [wireless-security]
abstract: Last night, I came across an article in a WeChat group about how a family member's phone was stolen, and criminal gangs used the SIM card (primarily SMS verification codes) as their entry point to launch a series of attacks. Although the author took timely remedial measures, these attacks still caused significant losses to the victim, such as unauthorized micro-loans. I reflected on why this attack succeeded and how to defend against such attacks, and I'm sharing my thoughts here.
---

Last night, I came across an article in a WeChat group about how a family member's phone was stolen, and criminal gangs used the SIM card (primarily SMS verification codes) as their entry point to launch a series of attacks. Although the author took timely remedial measures, these attacks still caused significant losses to the victim, such as unauthorized micro-loans. I reflected on why this attack succeeded and how to defend against such attacks, and I'm sharing my thoughts here.

Due to the widespread adoption of authentication methods like SMS verification codes and one-tap login via phone numbers, **SIM cards have essentially become a root of trust**. Once this root of trust is broken, you can only hope that downstream services have sufficient risk management and security policies to block attackers. However, this process is also constrained by the weakest link principle, so... once attackers get hold of a SIM card, there's far too much they can do.

The author also proposed their solution: **SIM card PIN + lock screen (without showing notification details on the lock screen)**. But even with this, is it truly safe?

### SIM Card PIN + Hidden Lock Screen Notifications Isn't Secure Either

Upon careful consideration, the starting point of these attacks is the SIM card. Hiding notification details on the lock screen prevents attackers from obtaining SMS verification codes when they cannot unlock the phone (most likely), while the SIM card PIN requires entering a password before the SIM can register on the network when moved to a new phone. These two measures seem to defend against this type of attack.

But is this really the case? Not necessarily.

**Phone number sniffing and SMS sniffing** are now quite mature technologies. The former can capture phone numbers of nearby active devices, while the latter can intercept SMS messages for a specific phone number on 2G networks. Therefore, even if you hide notification details on the lock screen and have a SIM card PIN, attackers can still use these techniques to obtain phone verification codes and launch the same attacks.

Both SMS sniffing and phone number sniffing can only be performed on 2G networks. Of course, this isn't difficult for attackers—on one hand, they can find an environment with poor 3G/4G signal where devices can only connect to 2G; on the other hand, they can also launch **downgrade attacks** to force phones connected to LTE networks down to 2G. This technology is also quite mature.

### How to Defend Against These Attacks?

It's simple: in your cellular network settings, set the network mode to **4G only** or **5G/4G**.

### Is Unlocking SIM Card PIN via Customer Service with PUK Feasible?

Some people mentioned that SIM card PINs can be unlocked by obtaining the PUK code through customer service. This is indeed true, but this unlocking process requires the owner's phone number (and in some regions, ID number). Considering that when criminals get hold of a phone, all they have access to is the SIM card and an unlocked phone, if attackers don't use the **phone number sniffing** technique I mentioned earlier, they cannot obtain the owner's phone number (and ID number) as additional information, and therefore cannot unlock the PIN.

### SIM Cards: An Untrusted Root of Trust

Whether it's SIM card PINs or 4G-only mode, these are essentially treating symptoms rather than the root cause (who knows what other methods criminals might have).

How to address the root cause? Unfortunately, **SIM cards being one of the security trust roots for some vendors** is an established fact. As long as there's one service that binds your ID number and bank card number and assumes that whoever holds this SIM card must be you, criminals can obtain your ID number and bank card number through the SIM card (mainly via SMS verification codes), and then breach the defenses of slightly better-protected apps (that assume whoever holds the SIM card and knows the ID and bank card numbers must be you).

Since most apps now require binding a phone number for normal use, **abandoning the SIM card as a security anchor is almost impossible**.
Currently, the lowest-cost solution for a fundamental fix is to make this untrusted root of trust trustworthy again. **In plain language, prepare an infrequently-used number and register all accounts with this infrequently-used number**. Then find ways to ensure the security of this infrequently-used number's SIM card.

### Methods to Implement This Solution

There are many methods, such as:

- Get a phone number, keep it at home, and forward all its SMS to email.
- Get a device with eSIM (like a smartwatch) and ensure its security (the watch stays on your wrist).
- Use virtual numbers like Alibaba's disposable numbers or Google Voice for registration.

Of course, you don't have to do this. While defense measures like SIM card PINs don't address the root cause, they're still **better than nothing**, and combined with **immediately reporting loss and replacing the SIM card after losing your phone**, can block most criminal attacks. Even if not completely blocked, it significantly increases the cost for criminals to carry out attacks.
