<?php

use TSEWEB\PasswordPolicy\PasswordPolicy;

class PasswordPolicyTest extends PHPUnit_Framework_TestCase
{
	private static function powerSetPermutations($arr)
	{
		$power_set = self::powerSet($arr);
		$result = array();
		foreach ($power_set as $set) {
			$perms = self::permutations($set);
			$result = array_merge($result, $perms);
		}
		return $result;
	}

	private static function powerSet($in, $minLength = 1)
	{
		$count = count($in);
		$members = pow(2, $count);
		$return = array();
		for ($i = 0; $i < $members; $i++) {
			$b = sprintf("%0" . $count . "b", $i);
			$out = array();
			for ($j = 0; $j < $count; $j++) {
				if ($b{$j} == '1') {
					$out[] = $in[$j];
				}
			}
			if (count($out) >= $minLength) {
				$return[] = $out;
			}
		}
		return $return;
	}

	private static function factorial($int)
	{
		if ($int < 2) {
			return 1;
		}
		for ($f = 2; $int - 1 > 1; $f *= $int--) {}
		return $f;
	}

	private static function permutation($arr, $nth = null)
	{

		if ($nth === null) {
			return self::permutations($arr);
		}

		$result = array();
		$length = count($arr);

		while ($length--) {
			$f = self::factorial($length);
			$p = floor($nth / $f);
			$result[] = $arr[$p];
			self::arrayDeleteByKey($arr, $p);
			$nth -= $p * $f;
		}

		$result = array_merge($result, $arr);
		return $result;
	}

	private static function permutations($arr)
	{
		$p = array();
		for ($i = 0; $i < self::factorial(count($arr)); $i++) {
			$p[] = self::permutation($arr, $i);
		}
		return $p;
	}

	private static function arraydeleteByKey(&$array, $delete_key, $use_old_keys = FALSE)
	{

		unset($array[$delete_key]);

		if (!$use_old_keys) {
			$array = array_values($array);
		}

		return true;
	}

	private static function invokeMethod(&$object, $methodName, array $parameters = array())
	{
		$reflection = new \ReflectionClass(get_class($object));
		$method = $reflection->getMethod($methodName);
		$method->setAccessible(true);

		return $method->invokeArgs($object, $parameters);
	}

	public function testMinimumScoreGetterAndSetter()
	{
		$pwp = new PasswordPolicy();
		for ($i = 0; $i < 10; ++$i) {
			$rand = rand(-200, 200);
			$this->assertEquals($pwp, $pwp->minimumScore($rand));
			$expected = $rand;
			if ($rand>100) {
				$expected = 100;
			}
			else if ($rand<0) {
				$expected = 0;
			}
			$this->assertEquals($expected, $pwp->minimumScore());
		}
	}

	public function testMinimumPasswordLengthGetterAndSetter()
	{
		$pwp = new PasswordPolicy();
		for ($i = 0; $i < 10; ++$i) {
			$rand = rand(-20, 20);
			$this->assertEquals($pwp, $pwp->minimumPasswordLength($rand));
			$expected = $rand;
			if ($rand<0) {
				$expected = 0;
			}
			$this->assertEquals($expected, $pwp->minimumPasswordLength());
		}
	}

	public function testMinimumComplexityGetterAndSetter()
	{
		$pwp = new PasswordPolicy();
		$availableComplexities = PasswordPolicy::getComplexities();

		foreach ($availableComplexities as $complexity) {
			$this->assertEquals($pwp, $pwp->minimumComplexity($complexity));
			$this->assertEquals($complexity, $pwp->minimumComplexity());
		}

		$this->assertEquals($pwp, $pwp->minimumComplexity(false));
		$this->assertFalse($pwp->minimumComplexity());

		$this->setExpectedException('Exception');
		$pwp->minimumComplexity('not a valid complexity');
		$this->setExpectedException('Exception');
		$pwp->minimumComplexity(true);
	}

	public function testAlphaUppercaseRequiredGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->alphaUppercaseRequired(true));
		$this->assertTrue($pwp->alphaUppercaseRequired());

		$this->assertEquals($pwp, $pwp->alphaUppercaseRequired(false));
		$this->assertFalse($pwp->alphaUppercaseRequired());
	}

	public function testAlphaLowercaseRequiredGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->alphaLowercaseRequired(true));
		$this->assertTrue($pwp->alphaLowercaseRequired());

		$this->assertEquals($pwp, $pwp->alphaLowercaseRequired(false));
		$this->assertFalse($pwp->alphaLowercaseRequired());
	}

	public function testNumberRequiredGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->numberRequired(true));
		$this->assertTrue($pwp->numberRequired());

		$this->assertEquals($pwp, $pwp->numberRequired(false));
		$this->assertFalse($pwp->numberRequired());
	}

	public function testSymbolRequiredGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->symbolRequired(true));
		$this->assertTrue($pwp->symbolRequired());

		$this->assertEquals($pwp, $pwp->symbolRequired(false));
		$this->assertFalse($pwp->symbolRequired());
	}

	public function testMidNumberOrSymbolRequiredGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->midNumberOrSymbolRequired(true));
		$this->assertTrue($pwp->midNumberOrSymbolRequired());

		$this->assertEquals($pwp, $pwp->midNumberOrSymbolRequired(false));
		$this->assertFalse($pwp->midNumberOrSymbolRequired());
	}

	public function testDisallowAlphasOnlyGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowAlphasOnly(true));
		$this->assertTrue($pwp->disallowAlphasOnly());

		$this->assertEquals($pwp, $pwp->disallowAlphasOnly(false));
		$this->assertFalse($pwp->disallowAlphasOnly());
	}

	public function testDisallowNumersOnlyGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowNumbersOnly(true));
		$this->assertTrue($pwp->disallowNumbersOnly());

		$this->assertEquals($pwp, $pwp->disallowNumbersOnly(false));
		$this->assertFalse($pwp->disallowNumbersOnly());
	}

	public function testDisallowConsecutiveAlphaLCGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowConsecutiveAlphaLC(true));
		$this->assertTrue($pwp->disallowConsecutiveAlphaLC());

		$this->assertEquals($pwp, $pwp->disallowConsecutiveAlphaLC(false));
		$this->assertFalse($pwp->disallowConsecutiveAlphaLC());
	}

	public function testDisallowConsecutiveAlphaUCGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowConsecutiveAlphaUC(true));
		$this->assertTrue($pwp->disallowConsecutiveAlphaUC());

		$this->assertEquals($pwp, $pwp->disallowConsecutiveAlphaUC(false));
		$this->assertFalse($pwp->disallowConsecutiveAlphaUC());
	}

	public function testDisallowConsecutiveNumbersGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowConsecutiveNumbers(true));
		$this->assertTrue($pwp->disallowConsecutiveNumbers());

		$this->assertEquals($pwp, $pwp->disallowConsecutiveNumbers(false));
		$this->assertFalse($pwp->disallowConsecutiveNumbers());
	}

	public function testDisallowRepeatedCharsGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowRepeatedChars(true));
		$this->assertTrue($pwp->disallowRepeatedChars());

		$this->assertEquals($pwp, $pwp->disallowRepeatedChars(false));
		$this->assertFalse($pwp->disallowRepeatedChars());
	}

	public function testDisallowSequentialAlphasGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowSequentialAlphas(true));
		$this->assertTrue($pwp->disallowSequentialAlphas());

		$this->assertEquals($pwp, $pwp->disallowSequentialAlphas(false));
		$this->assertFalse($pwp->disallowSequentialAlphas());
	}

	public function testDisallowSequentialNumbersGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowSequentialNumbers(true));
		$this->assertTrue($pwp->disallowSequentialNumbers());

		$this->assertEquals($pwp, $pwp->disallowSequentialNumbers(false));
		$this->assertFalse($pwp->disallowSequentialNumbers());
	}

	public function testDisallowSequentialSymbolsGetterAndSetter()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowSequentialSymbols(true));
		$this->assertTrue($pwp->disallowSequentialSymbols());

		$this->assertEquals($pwp, $pwp->disallowSequentialSymbols(false));
		$this->assertFalse($pwp->disallowSequentialSymbols());
	}

	public function testDisallowCommonPasswords ()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->disallowCommonPasswords(true));
		$this->assertTrue($pwp->disallowCommonPasswords());

		$this->assertEquals($pwp, $pwp->disallowCommonPasswords(false));
		$this->assertFalse($pwp->disallowCommonPasswords());
	}

	public function testCommonPasswordsFile ()
	{
		$pwp = new PasswordPolicy();

		$this->assertEquals($pwp, $pwp->commonPasswordsFile($pwp->commonPasswordsFile()));
	}

	public function testHasMinimumRequiredLength()
	{
		$pwp = new PasswordPolicy();
		$range = range(0, 10);
		$passwordLength = 5;
		$password = str_repeat('a', $passwordLength);

		foreach ($range as $minimumPasswordLength) {
			$this->assertEquals($pwp, $pwp->minimumPasswordLength($minimumPasswordLength));
			if ($minimumPasswordLength <= $passwordLength) {
				$this->assertTrue($pwp->hasMinimumRequiredLength($password));
			}
			else {
				$this->assertFalse($pwp->hasMinimumRequiredLength($password));
			}
		}
	}
	

	public function testHasAlphaUppercase()
	{
		$pwp = new PasswordPolicy();
		$permutationsWithUC = self::permutations(str_split('Abc.1'));
		$permutationsWithoutUC = self::permutations(str_split('abc.1'));

		foreach ($permutationsWithUC as $str) {
			$this->assertTrue($pwp->hasAlphaUppercase(join('', $str)));
		}

		foreach ($permutationsWithoutUC as $str) {
			$this->assertFalse($pwp->hasAlphaUppercase(join('', $str)));
		}
	}
	

	public function testHasAlphaLowercase()
	{
		$pwp = new PasswordPolicy();
		$permutationsWithLC = self::permutations(str_split('ABc.1'));
		$permutationsWithoutLC = self::permutations(str_split('ABC.1'));

		foreach ($permutationsWithLC as $str) {
			$this->assertTrue($pwp->hasAlphaLowercase(join('', $str)));
		}

		foreach ($permutationsWithoutLC as $str) {
			$this->assertFalse($pwp->hasAlphaLowercase(join('', $str)));
		}
	}
	

	public function testHasNumber()
	{
		$pwp = new PasswordPolicy();
		$permutationsWithNumber = self::permutations(str_split('ABc.1'));
		$permutationsWithoutNumber = self::permutations(str_split('ABC.'));

		foreach ($permutationsWithNumber as $str) {
			$this->assertTrue($pwp->hasNumber(join('', $str)));
		}

		foreach ($permutationsWithoutNumber as $str) {
			$this->assertFalse($pwp->hasNumber(join('', $str)));
		}
	}
	

	public function testHasSymbol()
	{
		$pwp = new PasswordPolicy();
		$permutationsWithSymbol = self::permutations(str_split('ABc.1'));
		$permutationsWithoutSymbol = self::permutations(str_split('ABC1'));

		foreach ($permutationsWithSymbol as $str) {
			$this->assertTrue($pwp->hasSymbol(join('', $str)));
		}

		foreach ($permutationsWithoutSymbol as $str) {
			$this->assertFalse($pwp->hasSymbol(join('', $str)));
		}
	}
	

	public function testHasMidNumberOrSymbol()
	{
		$pwp = new PasswordPolicy();
		$midChars = '.1';
		$midCharsArr = str_split($midChars);
		$other = 'Abc';
		$set = $midChars.$other;
		$permutations = self::permutations(str_split($set));
		$l = strlen($set);

		foreach ($permutations as $str) {
			$str = join('', $str);
			$hasMidChars = false;
			foreach ($midCharsArr as $midChar) {
				$midCharPosition = strpos($str, $midChar);
				if ($midCharPosition>0 && $midCharPosition<($l-1)) {
					$hasMidChars = true;
					break;
				}
			}
			if ($hasMidChars) {
				$this->assertTrue($pwp->hasMidNumberOrSymbol($str));
			}
			else {
				$this->assertFalse($pwp->hasMidNumberOrSymbol($str));
			}
		}
	}
	
	
	public function testHasAlphasOnly ()
	{
		$pwp = new PasswordPolicy();
		$onlyAlphaPermuations = self::permutations(str_split('AbCdE'));
		$mixedCharPermuations = self::permutations(str_split('AbC.1'));
		
		foreach ($onlyAlphaPermuations as $str) {
			$this->assertTrue($pwp->hasAlphasOnly(join('', $str)));
		}
		
		foreach ($mixedCharPermuations as $str) {
			$this->assertFalse($pwp->hasAlphasOnly(join('', $str)));
		}
	}
	
	
	public function testHasNumbersOnly ()
	{
		$pwp = new PasswordPolicy();
		$onlyNumberPermuations = self::permutations(str_split('01234'));
		$mixedCharPermuations = self::permutations(str_split('AbC.1'));
		
		foreach ($onlyNumberPermuations as $str) {
			$this->assertTrue($pwp->hasNumbersOnly(join('', $str)));
		}
		
		foreach ($mixedCharPermuations as $str) {
			$this->assertFalse($pwp->hasNumbersOnly(join('', $str)));
		}
	}
	
	
	public function testHasRepeatedChars ()
	{
		$pwp = new PasswordPolicy();
		$repeatedCharPermuations = self::permutations(str_split('AAB.1'));
		$mixedCharPermuations = self::permutations(str_split('AbC.1'));
		
		foreach ($repeatedCharPermuations as $str) {
			$this->assertTrue($pwp->hasRepeatedChars(join('', $str)));
		}
		
		foreach ($mixedCharPermuations as $str) {
			$this->assertFalse($pwp->hasRepeatedChars(join('', $str)));
		}
	}
	
	
	public function testHasConsecutiveAlphaUC ()
	{
		$pwp = new PasswordPolicy();
		$withConsecutivePermutations = self::permutations(array('AB','c','.','1'));
		$withoutConsecutivePermutations = self::permutations(array('A','b','c','.','1'));
		
		foreach ($withConsecutivePermutations as $str) {
			$this->assertTrue($pwp->hasConsecutiveAlphaUC(join('', $str)));
		}
		
		foreach ($withoutConsecutivePermutations as $str) {
			$this->assertFalse($pwp->hasConsecutiveAlphaUC(join('', $str)));
		}
	}
	
	
	public function testHasConsecutiveAlphaLC ()
	{
		$pwp = new PasswordPolicy();
		$withConsecutivePermutations = self::permutations(array('ab','C','.','1'));
		$withoutConsecutivePermutations = self::permutations(array('a','B','C','.','1'));
		
		foreach ($withConsecutivePermutations as $str) {
			$this->assertTrue($pwp->hasConsecutiveAlphaLC(join('', $str)));
		}
		
		foreach ($withoutConsecutivePermutations as $str) {
			$this->assertFalse($pwp->hasConsecutiveAlphaLC(join('', $str)));
		}
	}
	
	
	public function testHasConsecutiveNumbers ()
	{
		$pwp = new PasswordPolicy();
		$withConsecutivePermutations = self::permutations(array('A','b','.','12'));
		$withoutConsecutivePermutations = self::permutations(array('A','b','c','.','1'));
		
		foreach ($withConsecutivePermutations as $str) {
			$this->assertTrue($pwp->hasConsecutiveNumbers(join('', $str)));
		}
		
		foreach ($withoutConsecutivePermutations as $str) {
			$this->assertFalse($pwp->hasConsecutiveNumbers(join('', $str)));
		}
	}
	
	
	public function testCountSequentialChars ()
	{
		$pwp = new PasswordPolicy();
		
		$this->assertEquals(0, $pwp->countSequentialChars('acegi', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(1, $pwp->countSequentialChars('abc', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(2, $pwp->countSequentialChars('abcd', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(3, $pwp->countSequentialChars('abcde', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(0, $pwp->countSequentialChars('igeca', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(1, $pwp->countSequentialChars('cba', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(2, $pwp->countSequentialChars('dcba', PasswordPolicy::ALHPAS_LC));
		$this->assertEquals(3, $pwp->countSequentialChars('edcba', PasswordPolicy::ALHPAS_LC));
	}
	
	
	public function testHasSequentialAlphas ()
	{
		$pwp = new PasswordPolicy();
		$withSequentialPermutations = self::permutations(array('AbC','.','1'));
		$withReversedSequentialPermutations = self::permutations(array('CbA','.','1'));
		$withoutSequentialPermutations = self::permutations(array('A','b','.','1','2'));
		
		foreach ($withSequentialPermutations as $str) {
			$this->assertTrue($pwp->hasSequentialAlphas(join('', $str)));
		}
		
		foreach ($withReversedSequentialPermutations as $str) {
			$this->assertTrue($pwp->hasSequentialAlphas(join('', $str)));
		}
		
		foreach ($withoutSequentialPermutations as $str) {
			$this->assertFalse($pwp->hasSequentialAlphas(join('', $str)));
		}
	}
	
	
	public function testHasSequentialNumbers ()
	{
		$pwp = new PasswordPolicy();
		$withSequentialPermutations = self::permutations(array('123','a', 'B','.'));
		$withReversedSequentialPermutations = self::permutations(array('321','a', 'B','.'));
		$withoutSequentialPermutations = self::permutations(array('1','2','a','B','.'));
		
		foreach ($withSequentialPermutations as $str) {
			$this->assertTrue($pwp->hasSequentialNumbers(join('', $str)));
		}
		
		foreach ($withReversedSequentialPermutations as $str) {
			$this->assertTrue($pwp->hasSequentialNumbers(join('', $str)));
		}
		
		foreach ($withoutSequentialPermutations as $str) {
			$this->assertFalse($pwp->hasSequentialNumbers(join('', $str)));
		}
	}
	
	
	public function testHasSequentialSymbols ()
	{
		$pwp = new PasswordPolicy();
		$symbols = PasswordPolicy::SYMBOLS;
		$subset = substr($symbols, rand(0, strlen($symbols)-3), 3);
		$reversedSubset = substr(strrev($symbols), rand(0, strlen($symbols)-3), 3);
		$withConsecutivePermutations = self::permutations(array('A','b','1',$subset));
		$withReversedConsecutivePermutations = self::permutations(array('A','b','1',$reversedSubset));
		$withoutConsecutivePermutations = self::permutations(array('A','b','c','.','1'));
		
		foreach ($withConsecutivePermutations as $str) {
			$this->assertTrue($pwp->hasSequentialSymbols(join('', $str)));
		}
		
		foreach ($withReversedConsecutivePermutations as $str) {
			$this->assertTrue($pwp->hasSequentialSymbols(join('', $str)));
		}
		
		foreach ($withoutConsecutivePermutations as $str) {
			$this->assertFalse($pwp->hasSequentialSymbols(join('', $str)));
		}
	}
	
	
	public function testMinimumBruteForceTimeInSeconds ()
	{
		$pwp = new PasswordPolicy();
		
		for ($i=0; $i<10; ++$i) {
			$rand = rand(0, 100000000);
			$this->assertEquals($pwp, $pwp->minimumBruteForceTimeInSeconds($rand));
			$this->assertEquals($rand, $pwp->minimumBruteForceTimeInSeconds());
		}
		
		$this->assertEquals($pwp, $pwp->minimumBruteForceTimeInSeconds(0));
		$this->assertEquals(0, $pwp->minimumBruteForceTimeInSeconds());
	}
	
	
	public function testBruteForceKeysPerSecond ()
	{
		$pwp = new PasswordPolicy();
		
		for ($i=0; $i<10; ++$i) {
			$rand = rand(0, 100000000);
			$this->assertEquals($pwp, $pwp->bruteForceKeysPerSecond($rand));
			$this->assertEquals($rand, $pwp->bruteForceKeysPerSecond());
		}
	}
	
	
	public function testHasPossibleWordAndNumber ()
	{
		$pwp = new PasswordPolicy();
		
		$wordPermutations = self::permutations(str_split('AbCd'));
		$withSymbolPermutations = self::permutations(str_split('AbCd.'));
		
		foreach ($wordPermutations as $str) {
			$rand = rand(0, 100);
			$this->assertTrue($pwp->hasPossibleWordAndNumber(join('', $str).((string) $rand)));
		}
		
		foreach ($wordPermutations as $str) {
			$rand = rand(0, 100);
			$this->assertTrue($pwp->hasPossibleWordAndNumber(((string) $rand).join('', $str)));
		}
		
		foreach ($withSymbolPermutations as $str) {
			$rand = rand(0, 100);
			$this->assertFalse($pwp->hasPossibleWordAndNumber(join('', $str).((string) $rand)));
		}
		
		foreach ($withSymbolPermutations as $str) {
			$rand = rand(0, 100);
			$this->assertFalse($pwp->hasPossibleWordAndNumber(((string) $rand).join('', $str)));
		}
	}
	
	
	public function testIsCommonUsedPassword ()
	{
		$pwp = new PasswordPolicy();
		
		$this->assertTrue($pwp->isCommonUsedPassword('password'));
		$this->assertFalse($pwp->isCommonUsedPassword('This is a "GOOD" password!'));
	}
	
	
	public function testGetScore ()
	{
		$pwp = new PasswordPolicy();
		
		$this->assertEquals(0, $pwp->getScore(''));
		$this->assertEquals(0, $pwp->getScore('testing'));
		$this->assertEquals(100, $pwp->getScore('The fox turns 25 next year!'));
		$this->assertLessThan(50, $pwp->getScore('testing0'));
		$this->assertGreaterThan(50, $pwp->getScore('Testing0.$'));
	}
	
	
	public function testGetScoreBreakdown ()
	{
		$pwp = new PasswordPolicy();
		$pwp->minimumPasswordLength(10);
		$pwp->minimumBruteForceTimeInSeconds(60*60*24*365*10);
		$breakdown = $pwp->getScoreBreakdown('1st "GOOD" Password!');
		$this->assertInternalType(PHPUnit_Framework_Constraint_IsType::TYPE_ARRAY, $breakdown);
		
		$this->assertGreaterThan(0, $breakdown['minimum_length']);
		$this->assertGreaterThan(0, $breakdown['length_bonus']);
		$this->assertGreaterThan(0, $breakdown['minimum_length']);
		$this->assertGreaterThan(0, $breakdown['alpha_uc']);
		$this->assertGreaterThan(0, $breakdown['alpha_lc']);
		$this->assertGreaterThan(0, $breakdown['number']);
		$this->assertGreaterThan(0, $breakdown['symbol']);
		$this->assertGreaterThan(0, $breakdown['mid_number_or_symbol']);
		$this->assertLessThan(0, $breakdown['repeat_chars']);
		$this->assertLessThan(0, $breakdown['consecutive_alpha_lc']);
		$this->assertLessThan(0, $breakdown['consecutive_alpha_uc']);
		$this->assertGreaterThan(0, $breakdown['brute_force_time']);
		$this->assertEquals(0, $breakdown['common_password']);
	}
	
	
	public function testValidate ()
	{
		// Common password
		$pwp = new PasswordPolicy();
		$pwp->disallowCommonPasswords(true);
		$this->assertContains('common_password', $pwp->validate('password'));
		$this->assertTrue($pwp->validate('This is a "GOOD" password!'));
		
		// Minimum password length
		$pwp = new PasswordPolicy();
		$pwp->minimumPasswordLength(10);
		$this->assertContains('minimum_length', $pwp->validate('123'));
		$this->assertTrue($pwp->validate('1234567890'));
		
		// Require lowercase letter
		$pwp = new PasswordPolicy();
		$pwp->alphaLowerCaseRequired(true);
		$this->assertContains('alpha_lc', $pwp->validate('ABC.123'));
		$this->assertTrue($pwp->validate('abc.123'));
		
		// Require uppercase letter
		$pwp = new PasswordPolicy();
		$pwp->alphaUpperCaseRequired(true);
		$this->assertContains('alpha_uc', $pwp->validate('abc.123'));
		$this->assertTrue($pwp->validate('ABC.123'));
		
		// Do not allow only letters
		$pwp = new PasswordPolicy();
		$pwp->disallowAlphasOnly(true);
		$this->assertContains('alphas_only', $pwp->validate('AbCdE'));
		$this->assertTrue($pwp->validate('AbC.123'));
		
		// Do not allow consecutive lowercase letters
		$pwp = new PasswordPolicy();
		$pwp->disallowConsecutiveAlphaLC(true);
		$this->assertContains('consecutive_alpha_lc', $pwp->validate('AbcdE.1'));
		$this->assertTrue($pwp->validate('AbCdE.1'));
		
		// Do not allow consecutive uppercase letters
		$pwp = new PasswordPolicy();
		$pwp->disallowConsecutiveAlphaUC(true);
		$this->assertContains('consecutive_alpha_uc', $pwp->validate('aBCDe.1'));
		$this->assertTrue($pwp->validate('AbCdE.1'));
		
		// Do not allow consecutive numbers
		$pwp = new PasswordPolicy();
		$pwp->disallowConsecutiveNumbers(true);
		$this->assertContains('consecutive_numbers', $pwp->validate('AbC.123'));
		$this->assertTrue($pwp->validate('AbCdE.1'));
		
		// Do not allow only numbers
		$pwp = new PasswordPolicy();
		$pwp->disallowNumbersOnly(true);
		$this->assertContains('numbers_only', $pwp->validate('12345'));
		$this->assertTrue($pwp->validate('AbCdE.1'));
		
		// Do not allow repeated characters
		$pwp = new PasswordPolicy();
		$pwp->disallowRepeatedChars(true);
		$this->assertContains('repeat_chars', $pwp->validate('AAbC.1'));
		$this->assertTrue($pwp->validate('AbCD.1'));
		
		// Do not allow sequential letters
		$pwp = new PasswordPolicy();
		$pwp->disallowSequentialAlphas(true);
		$this->assertContains('sequential_alpha', $pwp->validate('AbC.1'));
		$this->assertTrue($pwp->validate('ABd.1'));
		
		// Do not allow sequential numbers
		$pwp = new PasswordPolicy();
		$pwp->disallowSequentialNumbers(true);
		$this->assertContains('sequential_number', $pwp->validate('AbC.123'));
		$this->assertTrue($pwp->validate('ABd.124'));
		
		// Do not allow sequential symbols
		$pwp = new PasswordPolicy();
		$pwp->disallowSequentialSymbols(true);
		$subset = substr(PasswordPolicy::SYMBOLS, rand(0, strlen(PasswordPolicy::SYMBOLS)-4), 3);
		$this->assertContains('sequential_symbol', $pwp->validate('AbC.1'.$subset));
		$this->assertTrue($pwp->validate('ABd...124'));
		
		// Require a number or symbol in the middle of the password
		$pwp = new PasswordPolicy();
		$pwp->midNumberOrSymbolRequired(true);
		$this->assertContains('mid_number_or_symbol', $pwp->validate('1AbC3'));
		$this->assertContains('mid_number_or_symbol', $pwp->validate('.AbC:'));
		$this->assertContains('mid_number_or_symbol', $pwp->validate('1AbC.'));
		$this->assertContains('mid_number_or_symbol', $pwp->validate('.AbC&'));
		$this->assertTrue($pwp->validate('ABd.fdkm4'));
		$this->assertTrue($pwp->validate('ABd4fdkm4'));
		
		// Require a minimum brute force time
		$pwp = new PasswordPolicy();
		$pwp->minimumBruteForceTimeInSeconds(60*60*24*365*10000);
		$this->assertContains('brute_force_time', $pwp->validate('testing1'));
		$this->assertTrue($pwp->validate('The quick brown fox JUMPS over the 1st lazy dog!'));
		
		// Require a minimum complexity
		$pwp = new PasswordPolicy();
		$pwp->minimumComplexity(PasswordPolicy::COMPLEXITY_VERY_STRONG);
		$this->assertContains('complexity', $pwp->validate('testing1'));
		$this->assertTrue($pwp->validate('The quick brown fox JUMPS over the 1st lazy dog!'));
		
		// Require a minimum score
		$pwp = new PasswordPolicy();
		$pwp->minimumScore(100);
		$this->assertContains('minimum_score', $pwp->validate('testing1'));
		$this->assertTrue($pwp->validate('The quick brown fox JUMPS over the 1st lazy dog!'));
		
		// Require a number
		$pwp = new PasswordPolicy();
		$pwp->numberRequired(true);
		$this->assertContains('number', $pwp->validate('Test.This'));
		$this->assertTrue($pwp->validate('The quick brown fox JUMPS over the 1st lazy dog!'));
		
		// Require a symbol
		$pwp = new PasswordPolicy();
		$pwp->symbolRequired(true);
		$this->assertContains('symbol', $pwp->validate('Test1This'));
		$this->assertTrue($pwp->validate('The quick brown fox JUMPS over the 1st lazy dog!'));
	}
}
