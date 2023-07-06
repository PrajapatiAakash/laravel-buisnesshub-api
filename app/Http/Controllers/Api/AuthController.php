<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Helpers\ApiResponse;
use Illuminate\Validation\Rules;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * This function is used for login user
     * @param Request $request
     */
    public function login(Request $request)
    {
        $fieldType = filter_var($request->get('email'), FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

        if (Auth::attempt([$fieldType => $request->get('email'), 'password' => $request->get('password')])) {
            $user = Auth::user();
            $token = $user->createToken('api-token')->plainTextToken;
            $user->sessionToken = $token;

            return ApiResponse::success($user, 'User has been succefully logged in.');
        }

        return ApiResponse::error('Please enter valid details for login.');
    }

    /**
     * This function is used for logout the user
     * @param Request $request
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return ApiResponse::success([], 'User has been succefully logged out.');
    }

    /**
     * This function is used for register the user
     */
    public function register(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:'.User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        if ($user) {

            return ApiResponse::success([], 'User has been registered successfully.');
        }

        return ApiResponse::error('Please enter valid details for register.');
    }
}
