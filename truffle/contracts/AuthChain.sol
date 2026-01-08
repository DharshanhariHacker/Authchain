
pragma solidity ^0.8.0;

contract AuthChain {
    struct User {
        string publicKey; 
        bool isActive;    
    }

    mapping(address => User) public users;

    function registerUser(string memory _publicKey) public {
        require(!users[msg.sender].isActive, "User already registered and active");
        users[msg.sender] = User(_publicKey, true);
    }

    function revokeUser() public {
        require(users[msg.sender].isActive, "User not registered or already revoked");
        users[msg.sender].isActive = false;
    }

    function getPublicKey(address _user) public view returns (string memory) {
        return users[_user].publicKey;
    }

    function isUserActive(address _user) public view returns (bool) {
        return users[_user].isActive;
    }

    struct Asset {
        string id;
        string description;
        string status;     
        address owner;
        uint256 registeredAt;
        bool exists;
        string category;     
        string proofHash;    
        string imageUrl;     
    }

    mapping(string => Asset) public assets;
    string[] public assetIds;

    event AssetRegistered(string indexed id, address indexed owner);
    event AssetStatusChanged(string indexed id, string status);
    event AssetTransfer(string indexed id, address indexed from, address indexed to, uint256 timestamp);

    function registerAsset(string memory _id, string memory _desc, string memory _category, string memory _proofHash, string memory _imageUrl, address _owner) public {
        require(!assets[_id].exists, "Asset ID already exists");
        
        assets[_id] = Asset(_id, _desc, "CLEAN", _owner, block.timestamp, true, _category, _proofHash, _imageUrl);
        assetIds.push(_id);
        
        emit AssetRegistered(_id, _owner);
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