// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AuthChain
 * @dev As described in the project specification.
 * This contract manages user identities for a passwordless authentication system.
 * It stores a public key (or metadata) and an active status for each user address.
 */
contract AuthChain {
    struct User {
        string publicKey; // Stores metadata, could be a real PEM public key
        bool isActive;    // Status of the user
    }

    // Maps a user's Ethereum address to their User struct
    mapping(address => User) public users;

    /**
     * @dev Registers a new user or re-registers an inactive user.
     * The public key is provided as a string. This could be metadata
     * or a full PEM-encoded public key.
     * @param _publicKey The public key or metadata string to associate with the user.
     */
    function registerUser(string memory _publicKey) public {
        // Require that the user is not already active.
        // A user can re-register if they were previously revoked.
        require(!users[msg.sender].isActive, "User already registered and active");
        users[msg.sender] = User(_publicKey, true);
    }

    /**
     * @dev Revokes a user's access.
     * This can only be called by the user themselves, acting as a
     * self-service "disable account" or "revoke key" function.
     */
    function revokeUser() public {
        // Require that the user is currently registered and active.
        require(users[msg.sender].isActive, "User not registered or already revoked");
        users[msg.sender].isActive = false;
    }

    /**
     * @dev Retrieves the stored public key string for a given user.
     * @param _user The address of the user.
     * @return string The public key or metadata string.
     */
    function getPublicKey(address _user) public view returns (string memory) {
        return users[_user].publicKey;
    }

    /**
     * @dev Checks if a user is registered and currently active.
     * This is the primary function the backend will call.
     * @param _user The address of the user to check.
     * @return bool True if the user is active, false otherwise.
     */
    function isUserActive(address _user) public view returns (bool) {
        return users[_user].isActive;
    }
}