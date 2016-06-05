<?php
/**
 * NOTICE OF LICENSE
 *
 * Licensed under the 3-clause BSD License.
 *
 * This source file is subject to the 3-clause BSD License that is
 * bundled with this package in the LICENSE file.
 *
 * @package    pwpolicy
 * @version    1.0
 * @author     Vincent Verbruggen
 * @license    MIT
 */
namespace TSEWEB\PasswordPolicy;

class PasswordPolicy
{
	/**
	 * Lowercase letters
	 * @var string
	 */
	const ALHPAS_LC = 'abcdefghijklmnopqrstuvwxyz';
	
	/**
	 * Uppercase letters
	 * @var string
	 */
	const ALHPAS_UC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
	
	/**
	 * Numbers
	 * @var string
	 */
	const NUMBERS = '01234567890';
	
	/**
	 * Symbols
	 * @var string
	 */
	const SYMBOLS = '²&é"\'(§è!çà)-!"#$%&\'()*+,-./<=>?@[\\]^_{|}~,;:=?./+|@#{[^{}[]^$´`';
	
	/**
	 * Complexities
	 * @var string
	 */
	const COMPLEXITY_VERY_WEAK = 'very weak';
	const COMPLEXITY_WEAK = 'weak';
	const COMPLEXITY_GOOD = 'good';
	const COMPLEXITY_STRONG = 'strong';
	const COMPLEXITY_VERY_STRONG = 'very strong';
	
	
	/**
	 * Minimal required total score to pass
	 * @var integer
	 */
	protected $_minimumScore = 0;
	
	/**
	 * Minimal required password length to check the score against
	 * @var integer
	 */
	protected $_minimumPasswordLength = 0;
	
	/**
	 * Minimal required complexity, set to false to disable.
	 * Accepted values: 'very weak', 'weak', 'good', 'strong' or 'very strong'
	 * @var string|boolean
	 */
	protected $_minimumComplexity = false;
	
	/**
	 * Set to true if the password must contain uppercase characters.
	 * @var boolean
	 */
	protected $_alphaUppercaseRequired = false;
	
	/**
	 * Set to true if the password must contain lowercase characters.
	 * @var boolean
	 */
	protected $_alphaLowercaseRequired = false;
	
	/**
	 * Set to true if the password must contain numbers.
	 * @var boolean
	 */
	protected $_numberRequired = false;
	
	/**
	 * Set to true if the password must contain symbols.
	 * @var boolean
	 */
	protected $_symbolRequired = false;
	
	/**
	 * Set to true if the password must contain symbols or numbers in the middle of the password.
	 * @var boolean
	 */
	protected $_midNumberOrSymbolRequired = false;
	
	/**
	 * Set to true if the password cannot consist of characters only.
	 * @var boolean
	 */
	protected $_disallowAlphasOnly = false;
	
	/**
	 * Set to true if the password cannot consist of numbers only.
	 * @var boolean
	 */
	protected $_disallowNumbersOnly = false;
	
	/**
	 * Set to true if the password cannot contain repeating characters.
	 * @var boolean
	 */
	protected $_disallowRepeatedChars = false;
	
	/**
	 * Set to true if the password cannot contain consecutive uppercase characters.
	 * @var boolean
	 */
	protected $_disallowConsecutiveAlphaUC = false;
	
	/**
	 * Set to true if the password cannot contain consecutive lowercase characters.
	 * @var boolean
	 */
	protected $_disallowConsecutiveAlphaLC = false;
	
	/**
	 * Set to true if the password cannot contain consecutive numbers.
	 * @var boolean
	 */
	protected $_disallowConsecutiveNumbers = false;
	
	/**
	 * Set to true if the password cannot contain 3 or more sequential characters.
	 * @var boolean
	 */
	protected $_disallowSequentialAlphas = false;
	
	/**
	 * Set to true if the password cannot contain 3 or more sequential numbers.
	 * @var boolean
	 */
	protected $_disallowSequentialNumbers = false;
	
	/**
	 * Set to true if the password cannot contain 3 or more sequential symbols (Dutch-Belgium keyboard and ASCII).
	 * @var boolean
	 */
	protected $_disallowSequentialSymbols = false;
	
	/**
	 * Set to true if the password cannot be one of the common used passwords.
	 * @var boolean
	 */
	protected $_disallowCommonPasswords = false;
	
	/**
	 * The minimum time in seconds required to brute-force a password.
	 * Defaults to 10 years (60 * 60 * 24 * 365 * 10 = 315360000 seconds).
	 * @var integer
	 */
	protected $_minimumBruteForceTimeInSeconds = 0;
	
	/**
	 * The number of keys a custom built system can try per second.
	 * @var integer
	 */
	protected $_bruteForceKeysPerSecond = 4000000000;
	
	/**
	 * Location of the text file containing the top 10000 most common passwords.
	 * @var string
	 */
	protected $_commonPasswordsFile = __DIR__ . DIRECTORY_SEPARATOR . '10k_most_common.txt';
	
	/**
	 * Multipliers for score calculation.
	 * @var integer
	 */
	protected $_lengthMultiplier = 4;
	protected $_alphaMultiplier = 2;
	protected $_numberMultiplier = 2;
	protected $_symbolMultiplier = 2;
	protected $_midNumberOrSymbolMultiplier = 3;
	protected $_consecutiveAlphaUCMultiplier = 2;
	protected $_consecutiveAlphaLCMultiplier = 2;
	protected $_consecutiveNumberMultiplier = 2;
	protected $_sequentialAlphaMultiplier = 2;
	protected $_sequentialNumberMultiplier = 2;
	protected $_sequentialSymbolMultiplier = 2;
	protected $_possibleWordAndNumberMultiplier = 2;
	protected $_repetitionMultiplier = 2;
	
	/**
	 * Array containing the accepted complexities
	 * @var array
	 */
	protected static $_complexities = array(
		0 => self::COMPLEXITY_VERY_WEAK,
		1 => self::COMPLEXITY_WEAK,
		2 => self::COMPLEXITY_GOOD,
		3 => self::COMPLEXITY_STRONG,
		4 => self::COMPLEXITY_VERY_STRONG,
	);
	
	/**
	 * Class constructor
	 */
	public function __construct ()
	{
	}
	
	
	/**
	 * Get or set the minimum required score (between 0 and 100).
	 * @param integer $minimumScore
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|integer
	 */
	public function minimumScore ($minimumScore=null)
	{
		if ($minimumScore===null) {
			return $this->_minimumScore;
		}
		$this->_minimumScore = min(max((int) $minimumScore, 0), 100);
		return $this;
	}
	
	
	/**
	 * Get or set the minimum password length.
	 * @param integer $minimumPasswordLength
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|integer
	 */
	public function minimumPasswordLength ($minimumPasswordLength=null)
	{
		if ($minimumPasswordLength===null) {
			return $this->_minimumPasswordLength;
		}
		$this->_minimumPasswordLength = max((int) $minimumPasswordLength, 0);
		return $this;
	}
	
	
	/**
	 * Get or set the minimum required complexity of the password.
	 * @param boolean|string $complexity
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|string
	 * @throws \Exception
	 */
	public function minimumComplexity ($complexity=null)
	{
		if ($complexity===null) {
			return $this->_minimumComplexity;
		}
		
		if ($complexity!==false && !in_array($complexity, self::$_complexities)) {
			throw new \Exception('Complexity must be one of: very weak, weak, good, strong or very strong');
		}
		
		$this->_minimumComplexity = $complexity;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement for uppercase alpha characters.
	 * @param boolean $required
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function alphaUppercaseRequired ($required=null)
	{
		if ($required===null) {
			return $this->_alphaUppercaseRequired;
		}
		$this->_alphaUppercaseRequired = (bool) $required;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement for lowercase alpha characters.
	 * @param boolean $required
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function alphaLowerCaseRequired ($required=null)
	{
		if ($required===null) {
			return $this->_alphaLowercaseRequired;
		}
		$this->_alphaLowercaseRequired = (bool) $required;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement for numeric characters.
	 * @param boolean $required
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function numberRequired ($required=null)
	{
		if ($required===null) {
			return $this->_numberRequired;
		}
		$this->_numberRequired = (bool) $required;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement for symbols.
	 * @param boolean $required
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function symbolRequired ($required=null)
	{
		if ($required===null) {
			return $this->_symbolRequired;
		}
		$this->_symbolRequired = (bool) $required;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement for numbers or symbols in the middle of the password.
	 * @param boolean $required
	 * @return TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function midNumberOrSymbolRequired ($required=null)
	{
		if ($required===null) {
			return $this->_midNumberOrSymbolRequired;
		}
		$this->_midNumberOrSymbolRequired = (bool) $required;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of letters only.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowAlphasOnly ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowAlphasOnly;
		}
		$this->_disallowAlphasOnly = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of numbers only.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowNumbersOnly ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowNumbersOnly;
		}
		$this->_disallowNumbersOnly = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of consecutive lowercase letters.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowConsecutiveAlphaLC ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowConsecutiveAlphaLC;
		}
		$this->_disallowConsecutiveAlphaLC = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of consecutive uppercase letters.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowConsecutiveAlphaUC ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowConsecutiveAlphaUC;
		}
		$this->_disallowConsecutiveAlphaUC = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of consecutive numbers.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowConsecutiveNumbers ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowConsecutiveNumbers;
		}
		$this->_disallowConsecutiveNumbers = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of repeated characters.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowRepeatedChars ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowRepeatedChars;
		}
		$this->_disallowRepeatedChars = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of repeated letters.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowSequentialAlphas ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowSequentialAlphas;
		}
		$this->_disallowSequentialAlphas = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of repeated numbers.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowSequentialNumbers ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowSequentialNumbers;
		}
		$this->_disallowSequentialNumbers = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the usage of repeated symbols.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowSequentialSymbols ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowSequentialSymbols;
		}
		$this->_disallowSequentialSymbols = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the minimum time in seconds required to brute-force a password.
	 * @param integer $timeInSeconds
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|integer
	 */
	public function minimumBruteForceTimeInSeconds ($timeInSeconds=null)
	{
		if ($timeInSeconds===null) {
			return $this->_minimumBruteForceTimeInSeconds;
		}
		$this->_minimumBruteForceTimeInSeconds = abs((int) $timeInSeconds);
		return $this;
	}
	
	
	/**
	 * Get or set the number of keys a custom built system can try per second.
	 * @param integer $keysPerSecond
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|integer
	 */
	public function bruteForceKeysPerSecond ($keysPerSecond=null)
	{
		if ($keysPerSecond===null) {
			return $this->_bruteForceKeysPerSecond;
		}
		$this->_bruteForceKeysPerSecond = abs((int) $keysPerSecond);
		return $this;
	}
	
	
	/**
	 * Get or set the requirement to disallow the use of common passwords.
	 * @param boolean $disallow
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|boolean
	 */
	public function disallowCommonPasswords ($disallow=null)
	{
		if ($disallow===null) {
			return $this->_disallowCommonPasswords;
		}
		$this->_disallowCommonPasswords = (bool) $disallow;
		return $this;
	}
	
	
	/**
	 * Get or set the file location of the common password list.
	 * @param string $filename
	 * @return \TSEWEB\PasswordPolicy\PasswordPolicy|string
	 */
	public function commonPasswordsFile ($filename=null)
	{
		if ($filename===null) {
			return $this->_commonPasswordsFile;
		}
		
		$filename = (string) $filename;
		if (!is_readable($filename) || !is_file($filename)) {
			throw new \Exception('The given location of the password file does not exist.');
		}
		
		$this->_commonPasswordsFile = $filename;
		return $this;
	}
	
	
	/**
	 * Returns true if the length of the given $str equals or is greater than
	 * the minimum password length, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasMinimumRequiredLength ($str)
	{
		return strlen($str) >= $this->_minimumPasswordLength;
	}
	
	
	/**
	 * Returns true if the given string contains an uppercase letter, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasAlphaUppercase ($str)
	{
		return strpbrk($str, self::ALHPAS_UC)!==false;
	}
	
	
	/**
	 * Returns true if the given string contains a lowercase letter, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasAlphaLowercase ($str)
	{
		return strpbrk($str, self::ALHPAS_LC)!==false;
	}
	
	
	/**
	 * Returns true if the given string contains a number, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasNumber ($str)
	{
		return strpbrk($str, self::NUMBERS)!==false;
	}
	
	
	/**
	 * Returns true if the given string contains a symbol, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasSymbol ($str)
	{
		return preg_match('/[^'.preg_quote(self::ALHPAS_UC.self::NUMBERS, '/').']/i', $str)!==0;
		//return strpbrk($str, self::SYMBOLS)!==false;
	}
	
	
	/**
	 * Returns true if the midst part of the given string contains a number or
	 * symbol, or false otherwise. The midst part is a substring of the given
	 * string excluding the first and last character of the string.
	 * @param string $str
	 * @return boolean
	 */
	public function hasMidNumberOrSymbol ($str)
	{
		$partial = (string) substr($str, 1, -1);
		return strpbrk($partial, self::NUMBERS.self::SYMBOLS)!==false;
	}
	
	
	/**
	 * Returns true if the given string only contains letters, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasAlphasOnly ($str)
	{
		return strlen(trim($str, self::ALHPAS_LC.self::ALHPAS_UC))==0;
	}
	
	
	/**
	 * Returns true if the given string only contains numbers, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasNumbersOnly ($str)
	{
		return strlen(trim($str, self::NUMBERS))==0;
	}
	
	
	/**
	 * Returns true if the given string contains repeated characters, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasRepeatedChars ($str)
	{
		$charCount = count_chars($str, 1);
		return array_sum($charCount) > count($charCount);
	}
	
	
	/**
	 * Returns true if the given string contains two or more consecutive uppercase
	 * letters, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasConsecutiveAlphaUC ($str)
	{
		return preg_match('/['.preg_quote(self::ALHPAS_UC, '/').']{2,}/', $str)!==0;
	}
	
	
	/**
	 * Returns true if the given string contains two or more consecutive lowercase
	 * letters, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasConsecutiveAlphaLC ($str)
	{
		return preg_match('/['.preg_quote(self::ALHPAS_LC, '/').']{2,}/', $str)!==0;
	}
	
	
	/**
	 * Returns true if the given string contains two or more consecutive numbers,
	 * or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasConsecutiveNumbers ($str)
	{
		return preg_match('/['.preg_quote(self::NUMBERS, '/').']{2,}/', $str)!==0;
	}
	
	
	/**
	 * Returns the number of sequential characters from the given stack found in
	 * the given string in a forward and reversed order.
	 * Each set of 3 sequential characters counts as one.
	 * E.g. a string 'abcde' contains two sets of 3 sequential characters.
	 * 'abc' is the first set, 'bcd' is the second set and 'cde' is the third set.
	 * @param string $str
	 * @param string $stack
	 * @return integer
	 */
	public function countSequentialChars ($str, $stack)
	{
		$c = 0;
		for ($s=0, $l=strlen($stack); $s<($l-2); ++$s) {
			$sFwd = substr($stack, $s, 3);
			$sRev = strrev($sFwd);

			if (strpos($str, $sFwd)!==false || strpos($str, $sRev)!==false) {
				++$c;
			}
		}

		return $c;
	}
	
	
	/**
	 * Returns true if the given string contains sequential letters, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasSequentialAlphas ($str)
	{
		return $this->countSequentialChars(strtolower($str), self::ALHPAS_LC)>0;
	}
	
	
	/**
	 * Returns true if the given string contains sequential numbers, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasSequentialNumbers ($str)
	{
		return $this->countSequentialChars($str, self::NUMBERS)>0;
	}
	
	
	/**
	 * Returns true if the given string contains sequential symbols, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasSequentialSymbols ($str)
	{
		return $this->countSequentialChars($str, self::SYMBOLS)>0;
	}
	
	
	/**
	 * Returns the complexity based on the score of the given string.
	 * @param string $str
	 * @return string
	 */
	public function getComplexity ($str)
	{
		$score = max(0, min($this->getScore($str), 100));
		$complexityIndex = min(max(0, ceil(($score+1) / (100 / count(self::$_complexities))) - 1), count(self::$_complexities)-1);
		return self::$_complexities[$complexityIndex];
	}
	
	
	/**
	 * Returns true if the given string has the minimal required complexity,
	 * or false otherwise.
	 * @param string $minimalRequiredComplexity
	 * @param string $str
	 * @return boolean
	 */
	public function hasMinimalRequiredComplexity ($minimalRequiredComplexity, $str)
	{
		$complexity = $this->getComplexity($str);
		$complexityIndex = array_search($complexity, self::$_complexities, true);
		$requiredComplexityIndex = array_search($minimalRequiredComplexity, self::$_complexities, true);
		return $complexityIndex >= $requiredComplexityIndex;
	}
	
	
	/**
	 * Returns true if the given string possibly contains a word and a number,
	 * or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function hasPossibleWordAndNumber ($str)
	{
		return preg_match('/^([a-z]+[0-9]+|[0-9]+[a-z]+)$/i', $str)!==0;
	}
	
	
	/**
	 * Returns true if the given string is a common used password, or false otherwise.
	 * @param string $str
	 * @return boolean
	 */
	public function isCommonUsedPassword ($str)
	{
		$found = false;
		$fh = fopen($this->commonPasswordsFile(), 'r');
		while (($buffer = fgets($fh))!==false) {
			if (stripos($buffer, $str)===0) {
				$found = true;
				break;
			}
		}
		fclose($fh);
		return $found;
	}
	
	
	/**
	 * Get the score breakdown of the given string.
	 * @param string $str
	 * @return array
	 */
	public function getScoreBreakdown ($str)
	{
		$l = strlen($str);
		$parts = str_split($str);
		
		$breakdown = array();
		
		// Common password
		$breakdown['common_password'] = $this->isCommonUsedPassword($str) ? -200 : 0;
		
		// Password length
		$breakdown['minimum_length'] = $this->_minimumPasswordLength && $this->hasMinimumRequiredLength($str) ? 2 : 0;
		$breakdown['length_bonus'] = $l * $this->_lengthMultiplier;
		
		// Uppercase characters
		$alphaUCParts = str_split(self::ALHPAS_UC);
		$alphaUCOccurrences = array_intersect($parts, $alphaUCParts);
		$alphaUCCount = array_sum(array_count_values($alphaUCOccurrences));
		if ($alphaUCCount > 0 && $alphaUCCount < $l) {	
			$breakdown['alpha_uc'] = (($l - $alphaUCCount) * $this->_alphaMultiplier);
		}
		
		// Lowercase characters
		$alphaLCParts = str_split(self::ALHPAS_LC);
		$alphaLCOccurrences = array_intersect($parts, $alphaLCParts);
		$alphaLCCount = array_sum(array_count_values($alphaLCOccurrences));
		if ($alphaLCCount > 0 && $alphaLCCount < $l) {	
			$breakdown['alpha_lc'] = (($l - $alphaLCCount) * $this->_alphaMultiplier);
		}
		
		// Numbers
		$numberParts = str_split(self::NUMBERS);
		$numberOccurrences = array_intersect($parts, $numberParts);
		$numberCount = array_sum(array_count_values($numberOccurrences));
		if ($numberCount > 0 && $numberCount < $l) {	
			$breakdown['number'] = $numberCount * $this->_numberMultiplier;
		}
		
		// Symbols
		$symbolParts = str_split(self::SYMBOLS);
		$symbolOccurrences = array_intersect($parts, $symbolParts);
		$symbolCount = array_sum(array_count_values($symbolOccurrences));
		if ($symbolCount > 0 && $symbolCount < $l) {	
			$breakdown['symbol'] = $symbolCount * $this->_symbolMultiplier;
		}
		
		// Mid numbers or symbols
		$numberOrSymbolParts = array_merge($numberParts, $symbolParts);
		$partialParts = str_split((string) substr($str, 1, -1));
		$numberOrSymbolOccurrences = array_intersect($partialParts, $numberOrSymbolParts);
		$numberOrSymbolCount = array_sum(array_count_values($numberOrSymbolOccurrences));
		if ($numberOrSymbolCount > 0) {
			$breakdown['mid_number_or_symbol'] = $numberOrSymbolCount * $this->_midNumberOrSymbolMultiplier;
		}
		
		// Point deductions for poor practices
		// Possible word and number
		if ($this->hasPossibleWordAndNumber($str)) {
			$breakdown['possible_word_and_number'] = -$l * $this->_possibleWordAndNumberMultiplier;
		}
		
		// Only alphabetical characters
		if (($alphaLCCount > 0 || $alphaUCCount > 0) && $symbolCount===0 && $numberCount===0) {
			$breakdown['alphas_only'] = -$l * $this->_alphaMultiplier;
		}
		
		// Only numbers
		if ($alphaLCCount===0 && $alphaUCCount===0 && $symbolCount===0 && $numberCount > 0) {
			$breakdown['numbers_only'] = -$l * $this->_numberMultiplier;
		}
		
		// Same character exists more than once
		$charCount = count_chars($str, 1);
		$repetitionCount = array_sum($charCount) - count($charCount);
		if ($repetitionCount > 0) {
			$breakdown['repeat_chars'] = -$repetitionCount * $this->_repetitionMultiplier;
		}
		
		// Consecutive uppercase letters exist
		$consecutiveAlphaUCParts = preg_split('/[^'.preg_quote(self::ALHPAS_UC, '/').']/', $str, -1, PREG_SPLIT_NO_EMPTY);
		$consecutiveAlphaUCCharCountPerPart = array_map(function($s){return strlen($s)-1;}, $consecutiveAlphaUCParts);
		$consecutiveAlphaUCCharCount = array_sum($consecutiveAlphaUCCharCountPerPart);
		if ($consecutiveAlphaUCCharCount > 0) {
			$breakdown['consecutive_alpha_uc'] = -($consecutiveAlphaUCCharCount * $this->_consecutiveAlphaUCMultiplier);
		}
		
		// Consecutive lowercase letters exist
		$consecutiveAlphaLCParts = preg_split('/[^'.preg_quote(self::ALHPAS_LC, '/').']/', $str, -1, PREG_SPLIT_NO_EMPTY);
		$consecutiveAlphaLCCharCountPerPart = array_map(function($s){return strlen($s)-1;}, $consecutiveAlphaLCParts);
		$consecutiveAlphaLCCharCount = array_sum($consecutiveAlphaLCCharCountPerPart);
		if ($consecutiveAlphaLCCharCount > 0) {
			$breakdown['consecutive_alpha_lc'] = -($consecutiveAlphaLCCharCount * $this->_consecutiveAlphaLCMultiplier);
		}
		
		// Consecutive numbers exist
		$consecutiveNumberParts = preg_split('/[^'.preg_quote(self::NUMBERS, '/').']/', $str, -1, PREG_SPLIT_NO_EMPTY);
		$consecutiveNumberCountPerPart = array_map(function($s){return strlen($s)-1;}, $consecutiveNumberParts);
		$consecutiveNumberCount = array_sum($consecutiveNumberCountPerPart);
		if ($consecutiveNumberCount > 0) {
			$breakdown['consecutive_numbers'] = -($consecutiveNumberCount * $this->_consecutiveNumberMultiplier);
		}
		
		// Sequential alpha strings exist (3 characters or more)
		$sequentialAlphaCount = $this->countSequentialChars(strtolower($str), self::ALHPAS_LC);
		if ($sequentialAlphaCount > 0) {
			$breakdown['sequential_alpha'] = -($sequentialAlphaCount * $this->_sequentialAlphaMultiplier);
		}
		
		// Sequential numeric strings exist (3 characters or more)
		$sequentialNumberCount = $this->countSequentialChars($str, self::NUMBERS);
		if ($sequentialNumberCount > 0) {
			$breakdown['sequential_number'] = -($sequentialNumberCount * $this->_sequentialNumberMultiplier);
		}
		
		// Sequential symbol strings exist (3 characters or more)
		$sequentialSymbolCount = $this->countSequentialChars($str, self::SYMBOLS);
		if ($sequentialSymbolCount > 0) {
			$breakdown['sequential_symbol'] = -($sequentialSymbolCount * $this->_sequentialSymbolMultiplier);
		}
		
		// Brute-force time
		if ($this->_minimumBruteForceTimeInSeconds) {
			$bruteForceTime = $this->getBruteForceTimeInSeconds($str);
			if ($bruteForceTime >= $this->_minimumBruteForceTimeInSeconds) {
				$breakdown['brute_force_time'] = 50;
			}
			else if ($bruteForceTime < $this->_minimumBruteForceTimeInSeconds) {
				$breakdown['brute_force_time'] = -50;
			}
		}
		
		return $breakdown;
	}
	
	
	/**
	 * Get the score of the given string.
	 * @param string $str
	 * @return integer
	 */
	public function getScore ($str)
	{
		return min(max(0, array_sum($this->getScoreBreakdown($str))), 100);
	}
	
	
	/**
	 * Get the estimated time in seconds required to brute force the given string.
	 * @param string $str
	 * @return integer
	 */
	public function getBruteForceTimeInSeconds ($str)
	{
		$uniqueChars = 0;
		$uniqueChars += $this->hasAlphaLowercase($str) ? 26 : 0;
		$uniqueChars += $this->hasAlphaUppercase($str) ? 26 : 0;
		$uniqueChars += $this->hasSymbol($str) ? count(array_unique(str_split(self::SYMBOLS))) : 0;
		$uniqueChars += $this->hasNumber($str) ? 10 : 0;
		return floor(pow($uniqueChars, strlen($str)) / $this->_bruteForceKeysPerSecond);
	}
	
	
	/**
	 * Returns true if the given string meets all the requirements.
	 * If the given string does not meet the requirements, an array that contains
	 * the failed requirements is returned.
	 * @param string $str
	 * @return boolean|array
	 */
	public function validate ($str)
	{
		$failedOn = array(
			'common_password' => $this->disallowCommonPasswords() ? $this->isCommonUsedPassword($str) : false,
			'minimum_length' => !$this->hasMinimumRequiredLength($str),
			'alpha_lc' => $this->alphaLowerCaseRequired() ? !$this->hasAlphaLowercase($str) : false,
			'alpha_uc' => $this->alphaUppercaseRequired() ? !$this->hasAlphaUppercase($str) : false,
			'alphas_only' => $this->disallowAlphasOnly() ? $this->hasAlphasOnly($str) : false,
			'numbers_only' => $this->disallowNumbersOnly() ? $this->hasNumbersOnly($str) : false,
			'consecutive_alpha_lc' => $this->disallowConsecutiveAlphaLC() ? $this->hasConsecutiveAlphaLC($str) : false,
			'consecutive_alpha_uc' => $this->disallowConsecutiveAlphaUC() ? $this->hasConsecutiveAlphaUC($str) : false,
			'consecutive_numbers' => $this->disallowConsecutiveNumbers() ? $this->hasConsecutiveNumbers($str) : false,
			'mid_number_or_symbol' => $this->midNumberOrSymbolRequired() ? !$this->hasMidNumberOrSymbol($str) : false,
			'number' => $this->numberRequired() ? !$this->hasNumber($str) : false,
			'symbol' => $this->symbolRequired() ? !$this->hasSymbol($str) : false,
			'repeat_chars' => $this->disallowRepeatedChars() ? $this->hasRepeatedChars($str) : false,
			'sequential_alpha' => $this->disallowSequentialAlphas() ? $this->hasSequentialAlphas($str) : false,
			'sequential_number' => $this->disallowSequentialNumbers() ? $this->hasSequentialNumbers($str) : false,
			'sequential_symbol' => $this->disallowSequentialSymbols() ? $this->hasSequentialSymbols($str) : false,
			'complexity' => $this->minimumComplexity() ? !$this->hasMinimalRequiredComplexity($this->minimumComplexity(), $str) : false,
			'brute_force_time' => $this->minimumBruteForceTimeInSeconds() ? $this->getBruteForceTimeInSeconds($str) < $this->_minimumBruteForceTimeInSeconds : false,
			'minimum_score' => $this->minimumScore() ? $this->getScore($str) < $this->minimumScore() : false,
		);
		
		$failedOnFiltered = array_filter($failedOn);
		return count($failedOnFiltered) ? array_keys($failedOnFiltered) : true;
	}
	
	
	/**
	 * Returns an array with the complexities.
	 * @return array
	 */
	public static function getComplexities ()
	{
		return self::$_complexities;
	}
}