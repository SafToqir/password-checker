# Password Strength Checker

A command-line tool that rates a password from **Very weak** to **Very strong** and explains how to improve it. It also checks whether the password has appeared in a known data breach, without ever sending the password over the internet.

```
$ python password_checker.py --no-breach-check
Password (input hidden):

Strength: █░░░░ Very weak (26.0 bits)
  - It's built on a common password ('summer') with extra characters added.
  - A word followed by a number or year is one of the first patterns attackers try.
  - Use at least 12 characters.
```

## How it works

**Entropy estimate.** The starting score is `length × log2(character pool size)`, where the pool grows with each type of character used (lowercase, uppercase, digits, symbols).

**Penalties for patterns attackers try first:**
- Passwords on a list of the most common ones, including leetspeak versions (`p@ssw0rd`)
- A common password with numbers or symbols bolted on (`Monkey99`, `Liverpool1!`)
- Word followed by a number or year (`Summer2024`)
- Sequences and keyboard walks (`abcd`, `4321`, `qwerty`, `asdf`)
- Repeated characters or chunks (`aaa`, `abcabc`)

**Breach check (k-anonymity).** The password is hashed with SHA-1 on your machine. Only the first 5 characters of the hash are sent to the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) API. The API returns every breached hash starting with those 5 characters, and the match is done locally. Neither the password nor its full hash leaves your computer.

## Usage

Requires Python 3.10+ and no third-party packages.

```bash
python password_checker.py                    # with breach check
python password_checker.py --no-breach-check  # offline
python -m unittest -v                         # run the tests
```

The exit code is `0` for Strong or Very strong and `1` otherwise, so it can be used in scripts.

## Limitations

The entropy figure is an estimate. A real attacker uses large wordlists and rules, so a password can score well here and still be guessable. For production use, a library such as [zxcvbn](https://github.com/dropbox/zxcvbn) models this more thoroughly.
