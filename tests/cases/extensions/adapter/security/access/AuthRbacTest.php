<?php
/**
 * li3_access plugin for Lithium: the most rad php framework.
 *
 * @author        Tom Maiaroto
 * @copyright     Copyright 2010, Union of RAD (http://union-of-rad.org)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_access\tests\cases\extensions\adapter\security\access;

use lithium\net\http\Request;
use lithium\security\Auth;

use li3_access\security\Access;

class AuthRbacTest extends \lithium\test\Unit {

	public function setUp() {
		Auth::config(array(
			'rbac_user' => array(
				'adapter' => 'li3_access\tests\mocks\extensions\adapter\auth\MockAuthAdapter'
			)
		));

		Access::config(array(
			'test_no_rules_configured' => array('adapter' => 'AuthRbac'),
			'test_check' => array(
				'adapter' => 'AuthRbac',
				'rules' => array(
					'allow' => array(
						'resources' => 'user',
						'match' => '*::*'
					)
				)
			),
			'test_closures' => array(
				'adapter' => 'AuthRbac',
				'rules' => array(
					array(
						'resources' => '*',
						'allow' => function($request, &$ruleOptions) {
							$ruleOptions['message'] = 'Test allow options set.';
							return $request->params['allow'] ? true : false;
						},
						'match' => array(
							function($request) {
								return $request->params['match'] ? true : false;
							},
							'controller' => 'Rbac',
							'action' => 'action'
						)
					)
				)
			),
			'test_allow_closure' => array(
				'adapter' => 'AuthRbac',
				'rules' => array(
					array(
						'resources' => '*',
						'match' => '*::*',
						'allow' => function($request, &$ruleOptions) {
							$ruleOptions['message'] = 'Test allow options set.';
							return $request->params['allow'] ? true : false;
						}
					)
				)
			),
			'test_allow_closure_match' => array(
				'adapter' => 'AuthRbac',
				'rules' => array(
					array(
						'resources' => '*',
						'match' => function($request) {
							return !empty($request->params['allow_match']);
						},
						'allow' => function($request, &$ruleOptions) {
							$ruleOptions['message'] = 'Test allow options set 2.';
							return $request->params['allow'] ? true : false;
						}
					)
				)
			),
			'test_message_override' => array(
				'adapter' => 'AuthRbac',
				'rules' => array(
					array(
						'allow' => false,
						'resources' => '*',
						'match' => '*::*'
					),
					array(
						'message' => 'Rule access denied message.',
						'redirect' => 'Users::login',
						'resources' => '*',
						'match' => 'Rbac::action'
					),
					array(
						'message' => 'Test no overwrite.',
						'redirect' => '/test_no_overwrite',
						'resources' => 'user',
						'match' => null
					)
				)
			)
		));
	}

	public function tearDown() {
		Auth::clear('rbac_user');
	}

	public function testCheck() {
		$request = new Request(array('params' => array(
			'library' => 'test_library',
			'controller' => 'Rbac',
			'action' => 'action'
		)));

		$guest = array();
		$user = array('username' => 'test', 'role' => 'user');

		$request->data = $guest;
		$expected = array(
			'message' => 'You are not authorized to access this page.',
			'redirect' => 'Users::login'
		);
		$result = Access::check('test_check', $guest, $request);
		$this->assertIdentical($expected, $result);

		$request->data = $user;
		$expected = array();
		$result = Access::check('test_check', $user, $request);
		$this->assertIdentical($expected, $result);
	}

	public function testCheckMessageOverride() {
		$request = new Request(array('params' => array(
			'library' => 'test_library',
			'controller' => 'Rbac',
			'action' => 'action'
		)));

		$guest = array();
		$user = array('username' => 'test', 'role' => 'user');

		$request->data = $guest;

		$expected = array('message' => 'Rule access denied message.', 'redirect' => 'Users::login');
		$result = Access::check('test_message_override', $guest, $request);
		$this->assertIdentical($expected, $result);

		$request->data = $user;
		$expected = array();
		$result = Access::check('test_message_override', $user, $request);
		$this->assertIdentical($expected, $result);
		
		$request->params = array(
			'controller' => 'Rbac',
			'action' => 'denied'
		);

		$request->data = $guest;
		$expected = array(
			'message' => 'You are not authorized to access this page.',
			'redirect' => 'Users::login'
		);
		$result = Access::check('test_message_override', $guest, $request);
		$this->assertIdentical($expected, $result);

		$request->data = $user;
		$expected = array(
			'message' => 'You are not authorized to access this page.',
			'redirect' => 'Users::login'
		);
		$result = Access::check('test_message_override', $user, $request);
		$this->assertIdentical($expected, $result);

		$request->data = $user;
		$expected = array('message' => 'Message override!', 'redirect' => '/new_redirect');
		$result = Access::check('test_message_override', $user, $request, array(
			'message' => 'Message override!',
			'redirect' => '/new_redirect'
		));
		$this->assertIdentical($expected, $result);
	}

	public function testParseMatch() {
		$params = array(
			'library' => 'test_library',
			'controller' => 'Rbac',
			'action' => 'action'
		);
		$request = new Request(array('params' => $params));

		$match = array(
			'library' => 'test_library',
			'controller' => 'Rbac',
			'action' => 'action'
		);
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = array('controller' => 'Rbac', 'action' => 'action');
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = array('library' => 'test_library', 'action' => 'action');
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = array('library' => 'test_library', 'controller' => 'Rbac');
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = array(
			'library' => 'test_no_match',
			'controller' => 'Rbac',
			'action' => 'action'
		);
		$this->assertFalse(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = 'Rbac::action';
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = 'Rbac::*';
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = '*::action';
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = '*::*';
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = array('library' => 'test_library', '*::*');
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = array('library' => 'test_no_match', '*::*');
		$this->assertFalse(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$match = null;
		$this->assertFalse(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));

		$test = function() { return true; };
		$this->assertTrue(Access::adapter('test_closures')->parseMatch(array($test), compact('request', 'params')));

		$test = function() { return false; };
		$this->assertFalse(Access::adapter('test_closures')->parseMatch(array($test), compact('request', 'params')));
		$this->assertFalse(Access::adapter('test_closures')->parseMatch(array(), compact('request', 'params')));

		$params = array(
			'controller' => 'lithium\test\Controller',
			'action' => 'index'
		);
		$request = new Request(array('params' => $params));
		$match = 'Controller::*';
		$this->assertFalse(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));
		$match = 'lithium\test\Controller::*';
		$this->assertTrue(Access::adapter('test_check')->parseMatch($match, compact('request', 'params')));
	}

	public function testClosures() {
		$request = new Request(array('params' => array(
			'controller' => 'Rbac', 'action' => 'action'
		)));

		$user = $request->data = array('username' => 'test', 'role' => 'user');
		
		$request->params['match'] = true;
		$request->params['allow'] = true;
		$result = Access::check('test_closures', $user, $request);
		$this->assertIdentical(array(), $result);

		$request->params['match'] = true;
		$request->params['allow'] = false;
		$expected = array('message' => 'Test allow options set.', 'redirect' => 'Users::login');
		$result = Access::check('test_closures', $user, $request);
		$this->assertIdentical($expected, $result);

		$request->params = array('controller' => 'Rbac', 'action' => 'denied');

		$request->params['match'] = true;
		$request->params['allow'] = true;
		$result = Access::check('test_closures', $user, $request);
		$expected = array(
			'message' => 'You are not authorized to access this page.',
			'redirect' => 'Users::login'
		);
		$this->assertIdentical($expected, $result);

		$request->params['allow'] = true;
		$result = Access::check('test_allow_closure', $user, $request);
		$expected = array();
		$this->assertIdentical($expected, $result);

		$request->params['allow'] = false;
		$result = Access::check('test_allow_closure', $user, $request);
		$expected = array('message' => 'Test allow options set.', 'redirect' => 'Users::login');
		$this->assertIdentical($expected, $result);

		$request->params['allow'] = true;
		$request->params['allow_match'] = true;
		$result = Access::check('test_allow_closure_match', $user, $request);
		$expected = array();
		$this->assertIdentical($expected, $result);

		$request->params['allow'] = false;
		$request->params['allow_match'] = true;
		$result = Access::check('test_allow_closure_match', $user, $request);
		$expected = array('message' => 'Test allow options set 2.', 'redirect' => 'Users::login');
		$this->assertIdentical($expected, $result);

		$request->params['allow'] = true;
		$request->params['allow_match'] = false;
		$result = Access::check('test_allow_closure_match', $user, $request);
		$expected = array('message' => 'You are not authorized to access this page.', 'redirect' => 'Users::login');
		$this->assertIdentical($expected, $result);
	}

	public function testNoRulesConfigured() {
		$request = new Request();

		$config = Access::config('test_no_rules_configured');
		$request->params = array('controller' => 'Rbac', 'action' => 'granted');

		$this->assertTrue(empty($config['roles']));
		$this->expectException('No rules defined for adapter configuration.');
		Access::check('test_no_rules_configured', array('guest' => null), $request);
	}
}

?>