// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title PaymentGateway
/// @notice Smart contract for processing payments using whitelisted tokens
contract PaymentGateway is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    event TokenWhitelisted(string tokenSymbol, address tokenAddress);
    event TokenUnwhitelisted(string tokenSymbol);
    event NativeTokensSwept(address indexed to, uint256 amount);
    event ERC20TokensSwept(
        address indexed token,
        address indexed to,
        uint256 amount
    );
    event PaymentSuccessful(
        address indexed user,
        uint256 amount,
        string tokenSymbol,
        address indexed tokenAddress,
        bytes32 indexed referenceNumber,
        uint256 expiryTime
    );

    error InvalidAddress(string context);
    error TokenNotWhitelisted(string tokenSymbol);
    error TokenAlreadyWhitelisted(string tokenSymbol);
    error EmptyTokenSymbol();
    error ZeroAmount();
    error PaymentExpired(uint256 currentTime, uint256 expiryTime);
    error InsufficientBalance(uint256 balance, uint256 amount);
    error IncorrectPaymentAmount(uint256 sent, uint256 expected);
    error TransferFailed(string tokenType);
    error NoTokensToSweep(string tokenType, uint256 balance);

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    address public safeWallet;

    mapping(string => address) public whitelistedTokens;

    modifier validAddress(address _address) {
        if (_address == address(0))
            revert InvalidAddress("validAddress modifier");
        _;
    }

    modifier onlyWhitelistedToken(string calldata tokenSymbol) {
        if (whitelistedTokens[tokenSymbol] == address(0))
            revert TokenNotWhitelisted(tokenSymbol);
        _;
    }

    modifier notWhitelisted(string calldata tokenSymbol) {
        if (bytes(tokenSymbol).length == 0) revert EmptyTokenSymbol();
        if (whitelistedTokens[tokenSymbol] != address(0))
            revert TokenAlreadyWhitelisted(tokenSymbol);
        _;
    }

    modifier validAmount(uint256 amount) {
        if (amount == 0) revert ZeroAmount();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the PaymentGateway contract with the specified safe wallet address.
    /// @param _safeWallet The address of the safe wallet for managing and securely storing funds.
    /// @param _admin The address of the admin who will have control over the contract.
    /// @param _upgrader The address of the upgrader who can upgrade the contract.
    function initialize(
        address _admin,
        address _upgrader,
        address _safeWallet
    )
        external
        initializer
        validAddress(_safeWallet)
        validAddress(_admin)
        validAddress(_upgrader)
    {
        safeWallet = _safeWallet;
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _upgrader);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    function setSafeWallet(
        address newSafeWallet
    ) external onlyRole(DEFAULT_ADMIN_ROLE) validAddress(newSafeWallet) {
        safeWallet = newSafeWallet;
    }

    function whitelistToken(
        string calldata tokenSymbol,
        address tokenAddress
    )
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        validAddress(tokenAddress)
        notWhitelisted(tokenSymbol)
    {
        whitelistedTokens[tokenSymbol] = tokenAddress;
        emit TokenWhitelisted(tokenSymbol, tokenAddress);
    }

    function unwhitelistToken(
        string calldata tokenSymbol
    ) external onlyRole(DEFAULT_ADMIN_ROLE) onlyWhitelistedToken(tokenSymbol) {
        delete whitelistedTokens[tokenSymbol];
        emit TokenUnwhitelisted(tokenSymbol);
    }

    /// @notice Allow the contract to receive native tokens (ETH)
    receive() external payable {}

    function processPayment(
        string calldata tokenSymbol,
        uint256 amount,
        uint256 expiryTime,
        bytes32 referenceNumber
    )
        external
        onlyWhitelistedToken(tokenSymbol)
        validAmount(amount)
        nonReentrant
    {
        if (block.timestamp > expiryTime)
            revert PaymentExpired(block.timestamp, expiryTime);
        address tokenAddress = whitelistedTokens[tokenSymbol];
        if (IERC20(tokenAddress).balanceOf(msg.sender) < amount)
            revert InsufficientBalance(
                IERC20(tokenAddress).balanceOf(msg.sender),
                amount
            );
        IERC20(tokenAddress).safeTransferFrom(msg.sender, safeWallet, amount);

        emit PaymentSuccessful(
            msg.sender,
            amount,
            tokenSymbol,
            tokenAddress,
            referenceNumber,
            expiryTime
        );
    }

    function processNativePayment(
        uint256 amount,
        uint256 expiryTime,
        bytes32 referenceNumber
    ) external payable validAmount(amount) nonReentrant {
        if (block.timestamp > expiryTime)
            revert PaymentExpired(block.timestamp, expiryTime);
        if (msg.value != amount)
            revert IncorrectPaymentAmount(msg.value, amount);

        (bool success, ) = safeWallet.call{value: msg.value}("");
        if (!success) revert TransferFailed("NATIVE");

        emit PaymentSuccessful(
            msg.sender,
            amount,
            "NATIVE",
            address(0),
            referenceNumber,
            expiryTime
        );
    }

    function sweepNativeTokens()
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        nonReentrant
    {
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoTokensToSweep("NATIVE", balance);

        (bool success, ) = safeWallet.call{value: balance}("");
        if (!success) revert TransferFailed("NATIVE");

        emit NativeTokensSwept(safeWallet, balance);
    }

    function sweepERC20Tokens(
        address tokenAddress
    )
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        validAddress(tokenAddress)
        nonReentrant
    {
        IERC20 token = IERC20(tokenAddress);
        uint256 balance = token.balanceOf(address(this));
        if (balance == 0) revert NoTokensToSweep("ERC20", balance);

        token.safeTransfer(safeWallet, balance);

        emit ERC20TokensSwept(tokenAddress, safeWallet, balance);
    }
}
