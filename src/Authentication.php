<?php

namespace JlnMay\NaMiddleware;

use \Psr\Http\Message\ServerRequestInterface as Request; 
use \Psr\Http\Message\ResponseInterface as Response;
use JlnMay\PersistentStorage\PsMemcached;
use JlnMay\NAuth\NAuth;
use Api\handlers\JsonException;
use Api\v2\services\LogService;

class Authentication
{
    private $oauth2Server; 
    private $logService; 
    private $request; 
    private $response; 

    public function __construct($oauth2Server, LogService $logService)
    {
        $this->oauth2Server = $oauth2Server; 
        $this->logService = $logService;    
    }

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
        $this->request = $request;
        $this->response = $response;

        // If allowInternalReadOperations attribute is present, that means that the incoming ips were validated, if the attribute 
        //  is set to true, we don't need to authenticate the incoming request at all 
        // This attribute is set in RestrictRoute middleware 
        if ($request->getAttribute("allowInternalReadOperations") != null && $request->getAttribute("allowInternalReadOperations")) {
            return $next($request, $response); 
        }

        if ($request->hasHeader("nauth-sso")) {
            $token = $request->getHeader("nauth-sso")[0];
            
            // Validating if the nauth-sso value match with nauth token bypass
            if ($token != getenv("NAUTH_BYPASS_TOKEN")) {
                $memcached = PsMemcached::getInstance();
                $uid = $this->getUid($token);
                
                $expirationDate = $memcached->has(array("key" => "mdadDateExpiration_" . $uid));
                
                if ($expirationDate != false) {
                    $expirationDate = $expirationDate["mdadDateExpiration"];
                }

                $currentDate = date("Y-m-d H:i:s A", time());
                
                // We check if the expiration date exists or if the current date is higher than expiration date (expired token)
                if (gettype($expirationDate) === "string" && $currentDate > $expirationDate) {
                    // Invalid token
                    $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
                    $this->logService->log($request, $response, json_encode($error), 401);
                    throw new JsonException(json_encode($error), 401);
                }

                if (!$expirationDate) {
                    $this->validateToken($token);
                    $uid = $this->getUid($token);
                    $this->validatePermissions($uid);
                } else {
                    $this->validatePermissions($uid);
                }
            }
        } else {
            // We check if Auhotization header or query string parameter is present 
            $params = $request->getQueryParams();
            $authorization = false; 
            foreach ($params as $key => $param) {
                if (strtolower($key) == "authorization") {
                    $authorization = true; 
                    $_GET["access_token"] = $param;
                    break; 
                }
            }
            
            if ($request->hasHeader("Authorization") || $authorization) {
                if (!$this->oauth2Server->verifyResourceRequest(\OAuth2\Request::createFromGlobals())) {
                    $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
                    $this->logService->log($request, $response, json_encode($error), 401);
                    throw new JsonException(json_encode($error), 401);
                } 
            } else {
                $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
                $this->logService->log($request, $response, json_encode($error), 401);
                throw new JsonException(json_encode($error), 401);
            }
        }

        return $next($request, $response);
    }

    /**
     * Gets the uid
     */
    private function getUid($token)
    {
        $memcached = PsMemcached::getInstance();
        $uid = $memcached->has(array("key" => md5("token_" . $token)));
            
        if ($uid != false) {
            $uid = $uid["uid"];
        }

        return $uid; 
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
        $position = array_search($naAccess, $permissions);

        /// GET applies for all endpoints 
        if ($position === false) {
            // There is no grant for the token
            $error = $this->buildErrorObject(403, "Authorized requestor does not have required grant for this operation.");
            $this->logService->log($this->request, $this->response, json_encode($error), 403);
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
        $nauth = new NAuth(getenv("NA_CLIENT_ID"), getenv("NA_CLIENT_SECRET"), getenv("NA_REDIRECT_URI"), getenv("NA_ENV"));
        $authResponse =  $nauth->introspect($token);

        $authResponseArray = json_decode($authResponse, true);
        $data = $authResponseArray["data"];

        if (isset($data["active"])) {
            $active = $data["active"]; 
            
            if ($active || $active == 1) {
                $originalDateExpiration = date("Y-m-d H:i:s A", $data["exp"]);
                $mdadDateExpiration = date("Y-m-d H:i:s", time());
                $mdadDateExpiration = date("Y-m-d H:i:s A", strtotime($mdadDateExpiration . ' +' . getenv("NA_TOKEN_LIVE")));
                $uid = $data["uid"];
                $memcached = PsMemcached::getInstance();
                
                // At this point we clear all values for the user in question
                
                $memcached->clear(array("key" => $token));
                $memcached->clear(array("key" => "originalDateExpiration_" . $uid));
                $memcached->clear(array("key" => "mdadDateExpiration_" . $uid));
                $memcached->clear(array("key" => "GET_" . $uid));
                
                $memcached->save(array("key" => 'originalDateExpiration_' . $uid, 
                    'store' => array("originalDateExpiration" => $originalDateExpiration)
                ));

                $memcached->save(array(
                    "key" => "mdadDateExpiration_" . $uid,
                    "store" => array("mdadDateExpiration" => $mdadDateExpiration)
                ));
                
                $userResponse = json_decode($nauth->getUserInfo($token), true);
                $data = $userResponse["data"];
                
                if (isset($data["groups"])) {
                    $groups = $data["groups"];
                    $position = array_search(getenv("NA_ACCESS"), $groups);
                    
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
                $this->logService->log($this->request, $this->response, json_encode($error), 401);
                throw new JsonException(json_encode($error), 401);   
            }
        } else {
            // The token was unable to be validated (No presence of the active attribute in NAuth response)
            $error = $this->buildErrorObject(401, "Authentication failed, due to missing or invalid credentials.");
            $this->logService->log($this->request, $this->response, json_encode($error), 401);
            throw new JsonException(json_encode($error), 401);   
        }
    }
}