<?php

namespace JlnMay\NaMiddleware;

use \Psr\Http\Message\ServerRequestInterface as Request; 
use \Psr\Http\Message\ResponseInterface as Response;
use JlnMay\PersistentStorage\PsMemcached;
use JlnMay\NAuth\NAuth;
use Api\handlers\JsonException;

class Authentication
{
    /**
     * Middleware invokable class
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $request  PSR7 request
     * @param  \Psr\Http\Message\ResponseInterface      $response PSR7 response
     * @param  callable                                 $next     Next middleware
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(Request $request, Response $response, $next)
    {
        if ($request->hasHeader("nauth-sso")) {
            $token = $request->getHeader("nauth-sso")[0];
            $memcached = PsMemcached::getInstance();
            $uid = $memcached->has(array("key" => md5("token_" . $token)));
            
            if ($uid != false) {
                $uid = $uid["uid"];
            }
            
            $expirationDate = $memcached->has(array("key" => "mdadDateExpiration_" . $uid));
            
            if ($expirationDate != false) {
                $expirationDate = $expirationDate["mdadDateExpiration"];
            }

            $currentDate = date("Y-m-d H:i:s A", time());
            
            // We check if the expiration date exists or if the current date is higher than expiration date (expired token)
            if (!$expirationDate || ($currentDate > $expirationDate)) {
                $this->validateToken($token);
                $this->validatePermissions($uid);
            } else {
                $this->validatePermissions($uid);
            }
        } else {
            // Missing token
            $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
            throw new JsonException(json_encode($error), 401);
        }
         
        $response = $next($request, $response);
        return $response;
    }

    /**
     * Validate token permissions 
     */
    private function validatePermissions($uid)
    {
        $memcached = PsMemcached::getInstance();
        $naAccess = $memcached->has(array(
            "key" => "NA_ACCESS_" . $uid 
        ));

        $naAccess = $naAccess["NA_ACCESS"];

        $permissions = [getenv("NA_ACCESS")];
        
        // Verifying is the user has the correct permissions
        $position = array_search($get, $permissions);

        /// GET applies for all endpoints 
        if ($position === false) {
            // There is no grant for the token
            $error = $this->buildErrorObject(403, "Authorized requestor does not have required grant for this operation.");
            throw new JsonException(json_encode($error), 403);
        }
    }

    /**	
	 * Builds error object.
	 */
	public function buildErrorObject($status, $message, $info = "", $reference = "")
    {
        return array(
            "code" => $status, 
            "message" => $message,
            "info" => $info, 
            "reference" => $reference
        );
	}
    
    /**
     * Validates the token
     * @param string $token Token
     */
    private function validateToken($token) 
    {
        $nauth = new NAuth(getenv("NA_CLIENT_ID"), getenv("NA_CLIENT_SECRET"));
        $authResponse =  $nauth->introspect(getenv("NA_ENV"), $token);

        $authResponseArray = json_decode($authResponse, true);
        $data = $authResponseArray["data"];

        if (isset($data["active"])) {
            $active = $data["active"]; 
            
            if ($active || $active == 1) {
                $originalDateExpiration = date("Y-m-d H:i:s A", $data["exp"]);
                $mdadDateExpiration = date("Y-m-d H:i:s", time());
                $mdadDateExpiration = date("Y-m-d H:i:s A", strtotime($mdadDateExpiration . ' +' . getenv("NA_TOKEN_LIVE") . ' hours'));
                $uid = $data["uid"];
                $memcached = PsMemcached::getInstance();
                
                // At this point we clear all values for the user in question
                
                $memcached->clear(array("key" => $token));
                $memcached->clear(array("key" => "originalDateExpiration_" . $uid));
                $memcached->clear(array("key" => "mdadDateExpiration_") . $uid);
                $memcached->clear(array("key" => "GET_" . $uid));
                
                $memcached->save(array("key" => 'originalDateExpiration_' . $uid, 
                    'store' => array("originalDateExpiration" => $originalDateExpiration)
                ));

                $memcached->save(array(
                    "key" => "mdadDateExpiration_" . $uid,
                    "store" => array("mdadDateExpiration" => $mdadDateExpiration)
                ));
                
                $userResponse = json_decode($nauth->getUserInfo(getenv("NA_ENV"), $token), true);
                $data = $userResponse["data"];
                
                if (isset($data["groups"])) {
                    $groups = $data["groups"];
                    $position = array_search(getenv("NA_ACCESS_"), $groups);
                    
                    // Read for everything (All GET endpoints)
                    if ($position > 0) {
                        $memcached->save(
                            array("key" => "NA_ACCESS_" . $uid, 
                                "store" => array(
                                    "NA_ACCESS" => 
                                    getenv("NA_ACCESS")
                                )
                            )
                        );
                    }
                }

                $memcached->save(array("key" => md5("token_" . $token), "store" => array("uid" => $uid)));
            } else {
                // Invalid token 
                $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
                throw new JsonException(json_encode($error), 401);   
            }
        } else {
            // The token was unable to be validated (No presence of the active attribute in NAuth response)
            $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
            throw new JsonException(json_encode($error), 401);   
        }
    }
}