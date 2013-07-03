<?php

namespace li3_access\extensions\adapter\security\access;

use lithium\security\Auth;
use lithium\util\Inflector;
use lithium\core\ConfigException;

class AuthRbac extends \lithium\core\Object {

	/**
	 * The actual rules defined in `Access::config`.
	 *
	 * @var array
	 */
	protected $_rules = null;

	/**
	 * Configuration that will be automatically assigned to class properties.
	 *
	 * @var array
	 */
	protected $_autoConfig = array('rules');

	/**
	 * The `Rbac` adapter will iterate the rbac data array.
	 *
	 * @param mixed $user     The user data array that holds all necessary information about
	 *                        the user requesting access. Or false (because `Auth::check()`
	 *                        can return `false`).
	 * @param mixed $params   The Lithium `Request` object, or an array with at least
	 *                        'request', and 'params'.
	 * @param array $options  An array of additional options.
	 * @return array          An empty array if access is allowed or an array with reasons for denial
	 *                        if denied.
	 */
	public function check($user, $params, array $options = array()) {
		if (empty($this->_rules)) {
			throw new ConfigException('No rules defined for adapter configuration.');
		}
		
		$defaults = array('user' => $user);
		$options += $defaults;

		$ruleDefaults = array(
			'resources' => '*',
			'message'   => '',
			'redirect' => '',
			'allow'    => true,
			'match'    => '*::*',
			'session'  => $user ?: false
		);

		$message = $options['message'];
		$redirect = $options['redirect'];

		$accessible = false;
		foreach ($this->_rules as $rule) {
			$rule += $ruleDefaults;
			
			if (is_callable($rule['allow'])) {
				$rule['allow'] = (array) $rule['allow'];
			}

			// check to see if this rule applies to the current request
			if (!static::parseMatch($rule['match'], $params)) {
				continue;
			}

			$accessible = static::_isAccessible($rule, $params, $options);
			if (!$accessible) {
				$message = !empty($rule['message']) ? $rule['message'] : $message;
				$redirect = !empty($rule['redirect']) ? $rule['redirect'] : $redirect;
			}
		}
		return !$accessible ? compact('message', 'redirect') : array();
	}

	/**
	 * Matches the current request parameters against a set of given parameters.
	 * Can match against a shorthand string (Controller::action) or a full array. If a parameter
	 * is provided then it must have an equivalent in the Request objects parmeters in order
	 * to validate. `*` is also acceptable to match a parameter without a specific value.
	 *
	 * @param mixed $match   A set of parameters to validate the request against.
	 * @param mixed $params  The Lithium `Request` object, or an array with at least
	 *                       'request', and 'params'
	 * @access public
	 * @return boolean       True if a match is found.
	 */
	public static function parseMatch($match, $params) {
		if (empty($match)) {
			return false;
		}

		if (is_array($match)) {
			$_params = $params;
			if (!static::_parseClosures($match, $params['request'], $_params)) {
				return false;
			}
		} elseif (is_callable($match)) {
			return (boolean) $match($params['request'], $params);
		}

		$matchParams = array();
		foreach ((array) $match as $key => $param) {
			if (is_string($param)) {
				if (preg_match('/^([A-Za-z0-9_\*\\\]+)::([A-Za-z0-9_\*]+)$/', $param, $regexMatches)) {
					$matchParams += array(
						'controller' => $regexMatches[1],
						'action' => $regexMatches[2]
					);
					continue;
				}
			}

			$matchParams[$key] = $param;
		}

		foreach ($matchParams as $type => $value) {
			if ($value === '*') {
				continue;
			}

			if ($type === 'controller') {
				$value = Inflector::underscore($value);
			}

			$exists_in_request = array_key_exists($type, $params['params']);
			if (!$exists_in_request || $value !== Inflector::underscore($params['params'][$type])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks if the Role grants access.
	 * If `allow` === false           => no access
	 * If `user` has no role          => no access
	 * If `allows` contains closures  => return closures
	 * Otherwise                      => grants access
	 *
	 * @param array $rule     The rule that is being processed (passed by reference).
	 * @param mixed $params   A lithium Request object.
	 * @param array $options  An array of additional options.
	 * @return boolean        $accessible
	 */
	protected static function _isAccessible(&$rule, $params, $options) {
		if ($rule['allow'] === false) {
			return false;
		}

		if (!static::_hasRole($rule['resources'], $options)) {
			return false;
		}

		if (is_array($rule['allow'])) {
			return static::_parseClosures($rule['allow'], $params['request'], $rule);
		}
		return true;
	}

	protected static function _hasRole($resources, array $options = array()) {
		$resources = (array) $resources;
		
		$roles = array(
			'*' // everyone
		);

		if($user = $options['user']) {
			if (isset($user['role'])) {
				$roles[] = 'user';
				$roles[] = $user['role'];
			}
		} else {
			$roles[] = 'guest';
		}

		if (in_array('*', $resources)) {
			return true;
		}
		//die(var_dump($roles));
		foreach ($roles as $role) {
			if (in_array($role, $resources)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Iterates over an array and runs any anonymous functions it finds. Returns true
	 * if all of the closures it runs evaluate to true. $match is passed by reference
	 * and any closures found are removed from it before the method has run it course.
	 *
	 * @param array $data       Dereferenced array.
	 * @param object $request   The Lithium `Request` object.
	 * @param array   $options  Dereferenced Array
	 * @return boolean
	 */
	protected static function _parseClosures(array &$data, $request, array &$options = array()) {
		$return = true;
		foreach ($data as $key => $item) {
			if (is_callable($item)) {
				if ($return === true) {
					$return = (boolean) $item($request, $options);
				}
				unset($data[$key]);
			}
		}
		return $return;
	}
}

?>
