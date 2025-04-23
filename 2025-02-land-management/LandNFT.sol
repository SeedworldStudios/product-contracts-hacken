// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "erc721a-upgradeable/contracts/extensions/ERC721AQueryableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title LandNFT Contract
/// @notice Upgradeable ERC721A-based contract for managing Land NFTs with EIP-712 support
contract LandNFT is
    Initializable,
    ERC721AQueryableUpgradeable,
    EIP712Upgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC2981Upgradeable
{
    error InvalidAddress(string role, address invalidAddress);
    error MaxSupplyExceeded(
        uint256 nftCount,
        uint256 currentSupply,
        uint256 maxRequests
    );
    error InvalidNFTType(string nftType);
    error CallerNotUser(address caller, address user);
    error InvalidSignature();
    error InvalidInputData(uint256 length, uint256 maxRequests);
    error MismatchedInputData(
        uint256 userNFTRightsDataLength,
        uint256 signaturesLength
    );
    error InvalidNFTCount(uint256 nftCount, uint256 maxNFTCount);
    error EmptyNFTTypes();
    error EmptyNFTType();
    error NFTTypeAlreadyExists(string nftType);
    error EmptyBaseURI();
    error InvalidTokenId(uint256 tokenId);
    error InvalidBatchSize(uint256 length, uint256 maxBatchTransfer);
    error ZeroMaxSupply();
    error MaxSupplyTooLow(uint256 currentSupply, uint256 newMaxSupply);

    event MaxSupplyUpdated(uint256 previousMaxSupply, uint256 newMaxSupply);
    event NFTTypeAdded(string indexed newNFTType, address indexed addedBy);
    event BaseURIUpdated(string newBaseURI, address indexed updatedBy);
    event NFTMinted(
        address indexed user,
        uint256 startTokenId,
        uint256 nftCount,
        string nftType,
        bytes32 indexed refNumber
    );

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    string private baseURI;
    bytes32 public userNFTRightsTypeHash;
    uint256 public constant MAX_REQUESTS = 10;
    uint256 public constant MAX_BATCH_TRANSFER = 100;
    uint256 public maxSupply;

    address public validator;

    mapping(string => bool) public nftTypeExists;
    mapping(address => uint256) public userNonces;
    mapping(uint256 => string) public mintedNFTTypes;

    struct InitParams {
        string name;
        string symbol;
        string[] nftTypes;
        string baseURI;
        address defaultAdmin;
        address upgrader;
        address validator;
        bytes32 userNFTRightsTypeHash;
        uint256 maxSupply;
    }

    struct UserMintRequest {
        address userAddress;
        string nftType;
        uint256 nftCount;
        bytes32 refNumber;
    }

    modifier notZeroAddress(address addr) {
        if (addr == address(0)) revert InvalidAddress("General", addr);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev Initializes the contract with roles, settings, and NFT types.
    /// @param params Struct containing:
    /// - name: The name of the ERC721A token.
    /// - symbol: The symbol of the ERC721A token.
    /// - nftTypes: Array of NFT types to be added at deployment.
    /// - baseURI: The base URI for the NFT metadata.
    /// - defaultAdmin: Address granted the default admin role.
    /// - upgrader: Address granted the upgrader role.
    /// - validator: Address granted the validator role.
    /// - userNFTRightsTypeHash: Hash for user NFT rights.
    /// - maxSupply: Maximum supply of NFTs.
    function initialize(
        InitParams calldata params
    ) public initializerERC721A initializer {
        __initializeContracts(params.name, params.symbol);
        __initializeRoles(
            params.defaultAdmin,
            params.upgrader,
            params.validator
        );
        __initializeNFTState(
            params.nftTypes,
            params.baseURI,
            params.userNFTRightsTypeHash,
            params.maxSupply
        );
    }

    function __initializeContracts(
        string memory name,
        string memory symbol
    ) internal {
        __ERC721A_init(name, symbol);
        __EIP712_init("NFT", "1");
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __ERC2981_init();
    }

    function __initializeRoles(
        address defaultAdmin,
        address upgrader,
        address initialValidator
    ) internal {
        if (defaultAdmin == address(0))
            revert InvalidAddress("DefaultAdmin", defaultAdmin);
        if (upgrader == address(0)) revert InvalidAddress("Upgrader", upgrader);
        if (initialValidator == address(0))
            revert InvalidAddress("Validator", initialValidator);

        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(UPGRADER_ROLE, upgrader);
        validator = initialValidator;
    }

    function __initializeNFTState(
        string[] calldata newNFTTypes,
        string calldata initialBaseURI,
        bytes32 initialUserNFTRightsTypeHash,
        uint256 newMaxSupply
    ) internal {
        userNFTRightsTypeHash = initialUserNFTRightsTypeHash;
        maxSupply = newMaxSupply;
        _addNFTTypes(newNFTTypes);
        _setBaseURI(initialBaseURI);
    }

    function _startTokenId() internal pure override returns (uint256) {
        return 1;
    }

    function _validateMintRequest(
        UserMintRequest calldata userData,
        bytes calldata signature
    ) internal view {
        if (!nftTypeExists[userData.nftType])
            revert InvalidNFTType(userData.nftType);
        if (userData.userAddress != msg.sender)
            revert CallerNotUser(msg.sender, userData.userAddress);
        bytes32 structHash = keccak256(
            abi.encode(
                userNFTRightsTypeHash,
                userData.userAddress,
                keccak256(bytes(userData.nftType)),
                userData.nftCount,
                userNonces[userData.userAddress] + 1,
                userData.refNumber
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        if (ECDSA.recover(hash, signature) != validator)
            revert InvalidSignature();
    }

    function getMaxNFTCount(
        uint256 numberOfObjects
    ) public pure returns (uint256) {
        if (numberOfObjects == 0 || numberOfObjects > MAX_REQUESTS)
            revert InvalidInputData(numberOfObjects, MAX_REQUESTS);
        return 100 / numberOfObjects;
    }

    /// @notice Mints NFT tokens for users based on their NFTRight data and corresponding signatures.
    /// @param userNFTRightsData An array of UserNFTRightsData structs containing the details for each nft minting request.
    /// @param signatures An array of signatures corresponding to each UserMintRequest, used to verify the authenticity of the requests.
    function mintNFT(
        UserMintRequest[] calldata userNFTRightsData,
        bytes[] calldata signatures
    ) external nonReentrant {
        _validateInputData(userNFTRightsData, signatures);
        uint256 maxNFTCount = getMaxNFTCount(userNFTRightsData.length);
        _validateNFTCount(userNFTRightsData, maxNFTCount);
        for (uint256 i = 0; i < userNFTRightsData.length; i++) {
            UserMintRequest calldata userData = userNFTRightsData[i];
            _processMintRequest(userData, signatures[i]);
        }
    }

    function _validateInputData(
        UserMintRequest[] calldata userNFTRightsData,
        bytes[] calldata signatures
    ) private pure {
        if (
            userNFTRightsData.length == 0 ||
            userNFTRightsData.length > MAX_REQUESTS
        ) revert InvalidInputData(userNFTRightsData.length, MAX_REQUESTS);
        if (userNFTRightsData.length != signatures.length)
            revert MismatchedInputData(
                userNFTRightsData.length,
                signatures.length
            );
    }

    function _validateNFTCount(
        UserMintRequest[] calldata userNFTRightsData,
        uint256 maxNFTCount
    ) private pure {
        for (uint256 i = 0; i < userNFTRightsData.length; i++) {
            UserMintRequest calldata userData = userNFTRightsData[i];
            if (userData.nftCount == 0 || userData.nftCount > maxNFTCount)
                revert InvalidNFTCount(userData.nftCount, maxNFTCount);
        }
    }

    function _processMintRequest(
        UserMintRequest calldata userData,
        bytes calldata signature
    ) private {
        _validateMintRequest(userData, signature);
        uint256 currentSupply = totalSupply();
        if (currentSupply + userData.nftCount > maxSupply)
            revert MaxSupplyExceeded(
                userData.nftCount,
                currentSupply,
                maxSupply
            );
        uint256 startTokenId = _nextTokenId();
        _mint(msg.sender, userData.nftCount);
        for (uint256 j = 0; j < userData.nftCount; j++) {
            mintedNFTTypes[startTokenId + j] = userData.nftType;
        }
        userNonces[userData.userAddress]++;
        emit NFTMinted(
            msg.sender,
            startTokenId,
            userData.nftCount,
            userData.nftType,
            userData.refNumber
        );
    }

    function _addNFTTypes(string[] memory newNFTTypes) internal {
        uint256 length = newNFTTypes.length;
        if (length == 0) revert EmptyNFTTypes();
        for (uint256 i = 0; i < length; i++) {
            string memory nftType = newNFTTypes[i];
            if (bytes(nftType).length == 0) revert EmptyNFTType();
            if (nftTypeExists[nftType]) revert NFTTypeAlreadyExists(nftType);
            nftTypeExists[nftType] = true;
            emit NFTTypeAdded(nftType, msg.sender);
        }
    }

    function addNFTTypes(
        string[] calldata newNFTTypes
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addNFTTypes(newNFTTypes);
    }

    function batchTransferFrom(
        address from,
        address to,
        uint256[] calldata tokenIds
    ) external notZeroAddress(from) notZeroAddress(to) {
        uint256 tokenLength = tokenIds.length;
        if (tokenLength == 0 || tokenLength > MAX_BATCH_TRANSFER)
            revert InvalidBatchSize(tokenLength, MAX_BATCH_TRANSFER);
        unchecked {
            for (uint256 i = 0; i < tokenLength; ++i) {
                safeTransferFrom(from, to, tokenIds[i]);
            }
        }
    }

    function setBaseURI(
        string calldata newBaseURI
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setBaseURI(newBaseURI);
    }

    function _setBaseURI(string calldata newBaseURI) internal {
        if (bytes(newBaseURI).length == 0) revert EmptyBaseURI();
        baseURI = newBaseURI;
        emit BaseURIUpdated(newBaseURI, msg.sender);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function tokenURI(
        uint256 tokenId
    )
        public
        view
        virtual
        override(ERC721AUpgradeable, IERC721AUpgradeable)
        returns (string memory)
    {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (bytes(baseURI).length == 0) {
            return "";
        }
        return string(abi.encodePacked(baseURI, toString(tokenId)));
    }

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        override(
            ERC721AUpgradeable,
            IERC721AUpgradeable,
            AccessControlUpgradeable,
            ERC2981Upgradeable
        )
        returns (bool)
    {
        return
            interfaceId == 0x80ac58cd || // ERC721
            interfaceId == 0x7965db0b || // AccessControl
            interfaceId == type(ERC2981Upgradeable).interfaceId || // ERC2981
            super.supportsInterface(interfaceId);
    }

    function getBaseURI() external view returns (string memory) {
        return baseURI;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    function setUserNFTRightsTypeHash(
        bytes32 newUserNFTRightsTypeHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        userNFTRightsTypeHash = newUserNFTRightsTypeHash;
    }

    function setValidator(
        address newValidator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) notZeroAddress(newValidator) {
        validator = newValidator;
    }

    function setMaxSupply(
        uint256 newMaxSupply
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newMaxSupply == 0) revert ZeroMaxSupply();
        if (totalSupply() >= newMaxSupply)
            revert MaxSupplyTooLow(totalSupply(), newMaxSupply);
        uint256 previousMaxSupply = maxSupply;
        maxSupply = newMaxSupply;
        emit MaxSupplyUpdated(previousMaxSupply, newMaxSupply);
    }

    function deleteDefaultRoyalty() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _deleteDefaultRoyalty();
    }

    function setDefaultRoyalty(
        address receiver,
        uint96 feeNumerator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setDefaultRoyalty(receiver, feeNumerator);
    }

    function setTokenRoyalty(
        uint256 tokenId,
        address receiver,
        uint96 feeNumerator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setTokenRoyalty(tokenId, receiver, feeNumerator);
    }
}
