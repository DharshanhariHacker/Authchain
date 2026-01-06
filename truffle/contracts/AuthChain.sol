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

    // --- ASSET MANAGEMENT ---
    struct Asset {
        string id;
        string description;
        string status;     // "CLEAN", "STOLEN"
        address owner;
        uint256 registeredAt;
        bool exists;
        string category;     // e.g. "Electronics"
        string proofHash;    // SHA256 Hash of the uploaded proof document
        string imageUrl;     // Path to stored image
    }

    mapping(string => Asset) public assets;
    string[] public assetIds; // For listing (Prototype only)

    event AssetRegistered(string indexed id, address indexed owner);
    event AssetStatusChanged(string indexed id, string status);
    event AssetTransfer(string indexed id, address indexed from, address indexed to, uint256 timestamp);

    function registerAsset(string memory _id, string memory _desc, string memory _category, string memory _proofHash, string memory _imageUrl, address _owner) public {
        require(!assets[_id].exists, "Asset ID already exists");
        
        assets[_id] = Asset(_id, _desc, "CLEAN", _owner, block.timestamp, true, _category, _proofHash, _imageUrl);
        assetIds.push(_id);
        
        emit AssetRegistered(_id, _owner);
        // Also emit a transfer from 0x0 to initial owner to start the chain
        emit AssetTransfer(_id, address(0), _owner, block.timestamp);
    }

    function setAssetStatus(string memory _id, string memory _status) public {
        require(assets[_id].exists, "Asset does not exist");
        require(assets[_id].owner == msg.sender || assets[_id].owner == address(0), "Not owner"); 
        
        assets[_id].status = _status;
        emit AssetStatusChanged(_id, _status);
    }

    function transferAsset(string memory _id, address _newOwner) public {
        require(assets[_id].exists, "Asset does not exist");
        // Check current owner. In this Gov Node model, msg.sender is the Admin/Backend.
        // The Admin is authorized to move assets IF the backend logic verified the user request.
        // Ideally, we would check tx.origin or a signature here, but for this prototype:
        // We TRUST the Admin (msg.sender) to only call this if Authorized.
        
        address currentOwner = assets[_id].owner;
        assets[_id].owner = _newOwner;
        
        emit AssetTransfer(_id, currentOwner, _newOwner, block.timestamp);
    }

    function getAsset(string memory _id) public view returns (
        string memory id,
        string memory description,
        string memory status,
        address owner,
        uint256 registeredAt,
        string memory category,
        string memory proofHash,
        string memory imageUrl
    ) {
        require(assets[_id].exists, "Asset not found");
        Asset memory a = assets[_id];
        return (a.id, a.description, a.status, a.owner, a.registeredAt, a.category, a.proofHash, a.imageUrl);
    }
    
    function getAssetCount() public view returns (uint256) {
        return assetIds.length;
    }
}