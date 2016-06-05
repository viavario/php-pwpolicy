# PasswordPolicy

A password policy enforcer.

## Installation

	composer require tseweb/php-pwpolicy

## Usage

```php
<?php
$pwp = new TSEWEB\PasswordPolicy();

// Set the minimum password length
$pwp->minimumPasswordLength(10);

// Require at least 1 uppercase letter
$pwp->alphaUppercaseRequired(true);

// Require at least 1 lowercase letter
$pwp->alphaLowercaseRequired(true);

// Require at least 1 number
$pwp->numberRequired(true);

// Require at least 1 symbol
$pwp->symbolRequired(true);

// Require at least 1 number or symbol that is not
// the first or last character of the password
$pwp->midNumberOrSymbolRequired(true);

// Do not allow letters only
$pwp->disallowAlphasOnly(true);

// Do not allow numbers only
$pwp->disallowNumbersOnly(true);

// Do not allow consecutive lowercase letters
// E.g. 'foobar' is not allowed, but 'FoObAr' is
$pwp->disallowConsecutiveAlphaLC(true);

// Do not allow consecutive uppercase letters
// E.g. 'FOOBAR' is not allowed, but 'FoObAr' is
$pwp->disallowConsecutiveAlphaUC(true);

// Do not allow consecutive numbers
// E.g. 'example564' is not allowed, but '5ex6ample4' is 
$pwp->disallowConsecutiveNumbers(true);

// Do not allow repeated characters
// E.g. 'foobar' is not allowed, but 'fozbar' is
$pwp->disallowRepeatedChars(true);

// Do not allow sequential letters
// E.g. 'SampleAbC' is not allowed, but 'ASampleBC' is
// E.g. 'SampleCbA' is not allowed, but 'ASampleCB' is
$pwp->disallowSequentialAlphas(true);

// Do not allow sequential numbers
// E.g. 'Sample123' is not allowed, but '1Sample23' is
// E.g. 'Sample654' is not allowed, but '6Sample54' is
$pwp->disallowSequentialNumbers(true);

// Do not allow sequential symbols
// E.g. 'Sample&é"' is not allowed, but '&Sampleé"' is
$pwp->disallowSequentialSymbols(true);

// Require a minimum score
// The score is based on various variables, e.g. password length,
// the use of letters (uppercase and lowercase), numbers, symbols,
// if the password contains a common used password, if it may be a word
// and a number, the estimated time to brute force the password, ...
$pwp->minimumScore(100);

// Require a minimum complexity
// The complexity is based on the score of the password
// Valid complexities are:
//   TSEWEB\PasswordPolicy::COMPLEXITY_VERY_WEAK
//   TSEWEB\PasswordPolicy::COMPLEXITY_WEAK
//   TSEWEB\PasswordPolicy::COMPLEXITY_GOOD
//   TSEWEB\PasswordPolicy::COMPLEXITY_STRONG
//   TSEWEB\PasswordPolicy::COMPLEXITY_VERY_STRONG
$pwp->minimumComplexity(TSEWEB\PasswordPolicy::COMPLEXITY_VERY_STRONG);

// Require a minimum time to brute force the password
$pwp->minimumBruteForceTimeInSeconds(60*60*24*365*100);
// A well built computer can try up to 4*10^9 passwords per second.
// When using a slow hashing method you can change the keys per second to
// a low number, e.g. 100 per second.
$pwp->bruteForceKeysPerSecond(4000000000);

// Do not allow commonly used passwords (top 10000)
$pwp->disallowCommonPasswords(true);

// Validate a password against the set policy
$validOrFails = $pwp->validate('testing');
if ($validOrFails===true) {
	// Password meets the requirements of the password policy
}
else if (is_array($validOrFails)) {
	// Password does not meet the requirements of the password policy
	// $validOrFails is an array containing the requirements the password failed on
	// E.g. array(
	//   'common_password', // Password is a common password
	//   'minimum_length', // Password is shorter than minimum length
	//   'alpha_lc', // Password does not contain a lowercase letter
	//   'alpha_uc', // Password does not contain an uppercase letter
	//   'alphas_only', // Password consists of letters only
	//   'numbers_only', // Password consists of numbers only
	//   'consecutive_alpha_lc', // Password contains consecutive lowercase letters
	//   'consecutive_alpha_uc', // Password contains consecutive uppercase letters
	//   'consecutive_numbers', // Password contains consecutive numbers 
	//   'mid_number_or_symbol', // Password does not contain a number or symbol in the middle
	//   'number', // Password does not contain a number
	//   'symbol', // Password does not contain a symbol
    //   'repeat_chars', // Password contains duplicate characters
	//   'sequential_alpha', // Password contains 3 or more sequential letters
	//   'sequential_number', // Password contains 3 or more sequential numbers
	//   'sequential_symbol', // Password contains 3 or more sequential symbols
	//   'complexity', // Password does not have the required complexity
	//   'brute_force_time', // Password can be brute force cracked in a shorter time than required
	//   'minimum_score' // Password does not meet the minimum score
	// );
}
```

