// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract NFTStaking is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IERC721Receiver
{
    using EnumerableSet for EnumerableSet.UintSet;

    error InvalidAddress();
    error NotStaker();
    error AlreadyStaked();
    error StakingDisabled();
    error InvalidDuration();
    error StakingNotEnded();
    error InvalidRange();
    error DurationExists();
    error DurationNotFound();
    error TooManyTokens();
    error EmptyTokens();
    error InvalidTokenState();
    error InvalidStakingType();
    error InvalidFixedDuration();
    error AlreadyUnstaked();
    error NotStaked();

    event NFTAddressUpdated(address indexed newAddress);
    event FixedStakingEnabled(bool enabled);
    event DynamicStakingEnabled(bool enabled);
    event StakingDurationAdded(uint256 durationDays);
    event StakingDurationRemoved(uint256 durationDays);
    event DynamicStakingRangeSet(uint256 minDuration, uint256 maxDuration);
    event NFTStaked(
        address indexed staker,
        uint256 indexed tokenId,
        uint256 duration
    );
    event NFTUnstaked(
        address indexed staker,
        uint256 indexed tokenId,
        uint256 unStakedAt
    );
    event StakingDurationExtended(
        address indexed staker,
        uint256 indexed tokenId,
        uint256 additionalDuration
    );

    struct StakingInfo {
        address staker;
        uint256 stakedAt;
        uint256 extendStakeTime;
        uint256 totalDuration;
        uint256 unStakedAt;
        uint256 duration;
        bool isStaked;
        bool isUnstaked;
        bool isFixed;
    }

    struct StakingConfig {
        bool fixedStakingEnabled;
        bool dynamicStakingEnabled;
        uint256 minDynamicStakingDuration;
        uint256 maxDynamicStakingDuration;
    }
    StakingConfig private stakingConfig;
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    IERC721 private nftContract;
    uint256[] public stakingDurations;
    uint256 public maxTokens;

    mapping(uint256 => StakingInfo) private stakingInfo;
    mapping(address => EnumerableSet.UintSet) private userStakedTokens;
    EnumerableSet.UintSet private allStakedTokens;

    modifier validAddress(address _address) {
        if (_address == address(0)) revert InvalidAddress();
        _;
    }
    modifier nonEmptyArray(uint256 arrayLength) {
        if (arrayLength == 0) revert EmptyTokens();
        _;
    }
    modifier validDuration(uint256 durationDays) {
        if (durationDays == 0) revert InvalidDuration();
        _;
    }
    modifier validTokenCount(uint256 length) {
        if (length > maxTokens) revert TooManyTokens();
        if (length == 0) revert EmptyTokens();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev Initializes the Staking contract with the specified NFT address and roles.
    /// @param _nftAddress The address of the NFT contract that will be staked.
    /// @param _admin The address of the admin who will have control over the contract.
    /// @param _upgrader The address of the upgrader who can upgrade the contract.
    /// @param _maxTokens Maximum number of tokens to stake per request.

    function initialize(
        address _nftAddress,
        address _admin,
        address _upgrader,
        uint256 _maxTokens
    )
        public
        initializer
        validAddress(_admin)
        validAddress(_upgrader)
        validAddress(_nftAddress)
    {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _upgrader);
        nftContract = IERC721(_nftAddress);
        maxTokens = _maxTokens;
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function validateFixedStakingDuration(
        uint256 durationDays
    ) internal view returns (bool) {
        for (uint256 i = 0; i < stakingDurations.length; i++) {
            if (stakingDurations[i] == durationDays) {
                return true;
            }
        }
        return false;
    }

    function stakeNFTsFixedDuration(
        uint256[] calldata tokenIds,
        uint256 durationDays
    ) external validTokenCount(tokenIds.length) nonReentrant {
        if (!stakingConfig.fixedStakingEnabled) revert StakingDisabled();
        if (!validateFixedStakingDuration(durationDays))
            revert InvalidFixedDuration();
        uint256 tokenLength = tokenIds.length;
        for (uint256 i = 0; i < tokenLength; i++) {
            uint256 tokenId = tokenIds[i];
            if (stakingInfo[tokenId].isStaked) revert AlreadyStaked();
            nftContract.safeTransferFrom(msg.sender, address(this), tokenId);
            stakingInfo[tokenId] = StakingInfo({
                staker: msg.sender,
                stakedAt: block.timestamp,
                extendStakeTime: 0,
                totalDuration: durationDays * 1 days,
                unStakedAt: 0,
                duration: durationDays * 1 days,
                isStaked: true,
                isUnstaked: false,
                isFixed: true
            });
            allStakedTokens.add(tokenId);
            userStakedTokens[msg.sender].add(tokenId);
            emit NFTStaked(msg.sender, tokenId, durationDays);
        }
    }

    function stakeNFTDynamicDuration(
        uint256[] calldata tokenIds,
        uint256 durationDays
    ) external validTokenCount(tokenIds.length) nonReentrant {
        if (!stakingConfig.dynamicStakingEnabled) revert StakingDisabled();
        if (
            durationDays < stakingConfig.minDynamicStakingDuration ||
            durationDays > stakingConfig.maxDynamicStakingDuration
        ) revert InvalidDuration();

        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];

            if (stakingInfo[tokenId].isStaked) revert AlreadyStaked();

            nftContract.safeTransferFrom(msg.sender, address(this), tokenId);

            stakingInfo[tokenId] = StakingInfo({
                staker: msg.sender,
                stakedAt: block.timestamp,
                extendStakeTime: 0,
                totalDuration: durationDays * 1 days,
                unStakedAt: 0,
                duration: durationDays * 1 days,
                isStaked: true,
                isUnstaked: false,
                isFixed: false
            });
            allStakedTokens.add(tokenId);
            userStakedTokens[msg.sender].add(tokenId);

            emit NFTStaked(msg.sender, tokenId, durationDays);
        }
    }

    function extendStakeDuration(
        uint256[] calldata tokenIds,
        uint256 additionalDurationDays
    ) external nonReentrant nonEmptyArray(tokenIds.length) {
        bool isFixed = stakingInfo[tokenIds[0]].isFixed;
        uint256 maxAllowedDuration = isFixed
            ? getMaxFixedStakingDuration()
            : stakingConfig.maxDynamicStakingDuration;

        if (isFixed && !validateFixedStakingDuration(additionalDurationDays)) {
            revert InvalidFixedDuration();
        }

        for (uint256 i = 0; i < tokenIds.length; i++) {
            _extendTokenStake(
                tokenIds[i],
                isFixed,
                additionalDurationDays,
                maxAllowedDuration
            );
        }
    }

    function _extendTokenStake(
        uint256 tokenId,
        bool isFixed,
        uint256 additionalDurationDays,
        uint256 maxAllowedDuration
    ) internal {
        StakingInfo storage stake = stakingInfo[tokenId];

        if (stake.staker != msg.sender) revert NotStaker();
        if (!stake.isStaked || stake.isUnstaked) revert InvalidTokenState();
        if (stake.isFixed != isFixed) revert InvalidStakingType();

        uint256 remainingTime = _getRemainingStakeTime(stake);
        uint256 newDuration = remainingTime + (additionalDurationDays * 1 days);

        if (newDuration > (maxAllowedDuration * 1 days))
            revert InvalidDuration();

        stake.extendStakeTime = block.timestamp;
        stake.totalDuration += (additionalDurationDays * 1 days);
        stake.duration = newDuration;

        emit StakingDurationExtended(
            msg.sender,
            tokenId,
            additionalDurationDays
        );
    }

    function _getRemainingStakeTime(
        StakingInfo storage stake
    ) internal view returns (uint256) {
        uint256 baseTime = stake.extendStakeTime > 0
            ? stake.extendStakeTime
            : stake.stakedAt;
        if (block.timestamp < baseTime + stake.duration) {
            return (baseTime + stake.duration) - block.timestamp;
        } else {
            return 0;
        }
    }

    function unstakeNFTs(
        uint256[] calldata tokenIds
    ) external nonReentrant nonEmptyArray(tokenIds.length) {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            _unstakeToken(tokenIds[i]);
        }
    }

    function _unstakeToken(uint256 tokenId) internal {
        StakingInfo storage info = stakingInfo[tokenId];

        if (info.isUnstaked) revert AlreadyUnstaked();
        if (!info.isStaked) revert NotStaked();
        if (info.staker != msg.sender) revert NotStaker();
        uint256 baseTime = info.extendStakeTime > 0
            ? info.extendStakeTime
            : info.stakedAt;
        if (block.timestamp < baseTime + info.duration)
            revert StakingNotEnded();

        nftContract.safeTransferFrom(address(this), msg.sender, tokenId);
        info.isUnstaked = true;
        info.isStaked = false;
        info.unStakedAt = block.timestamp;
        allStakedTokens.remove(tokenId);
        userStakedTokens[msg.sender].remove(tokenId);

        emit NFTUnstaked(msg.sender, tokenId, block.timestamp);
    }

    function getMaxFixedStakingDuration() public view returns (uint256) {
        uint256 maxDuration = 0;
        for (uint256 i = 0; i < stakingDurations.length; i++) {
            if (stakingDurations[i] > maxDuration) {
                maxDuration = stakingDurations[i];
            }
        }
        return maxDuration;
    }

    function isStakeMatured(uint256 tokenId) public view returns (bool) {
        StakingInfo memory stake = stakingInfo[tokenId];
        if (!stake.isStaked || stake.isUnstaked) return false;
        uint256 maturityTime = stake.extendStakeTime > 0
            ? stake.extendStakeTime + stake.duration
            : stake.stakedAt + stake.duration;
        return block.timestamp >= maturityTime;
    }

    function addStakingDuration(
        uint256 durationDays
    ) external onlyRole(DEFAULT_ADMIN_ROLE) validDuration(durationDays) {
        for (uint256 i = 0; i < stakingDurations.length; i++) {
            if (stakingDurations[i] == durationDays) revert DurationExists();
        }

        stakingDurations.push(durationDays);
        emit StakingDurationAdded(durationDays);
    }

    function removeStakingDuration(
        uint256 durationDays
    ) external onlyRole(DEFAULT_ADMIN_ROLE) validDuration(durationDays) {
        for (uint256 i = 0; i < stakingDurations.length; i++) {
            if (stakingDurations[i] == durationDays) {
                stakingDurations[i] = stakingDurations[
                    stakingDurations.length - 1
                ];
                stakingDurations.pop();
                emit StakingDurationRemoved(durationDays);
                return;
            }
        }
        revert DurationNotFound();
    }

    function setDynamicStakingRange(
        uint256 minDurationDays,
        uint256 maxDurationDays
    )
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        validDuration(minDurationDays)
        validDuration(maxDurationDays)
    {
        if (minDurationDays > maxDurationDays) revert InvalidRange();

        stakingConfig.minDynamicStakingDuration = minDurationDays;
        stakingConfig.maxDynamicStakingDuration = maxDurationDays;

        emit DynamicStakingRangeSet(minDurationDays, maxDurationDays);
    }

    function setFixedStakingEnabled(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        stakingConfig.fixedStakingEnabled = enabled;
        emit FixedStakingEnabled(enabled);
    }

    function setDynamicStakingEnabled(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        stakingConfig.dynamicStakingEnabled = enabled;
        emit DynamicStakingEnabled(enabled);
    }

    function getStakingInfo(
        uint256 tokenId
    ) external view returns (StakingInfo memory) {
        return stakingInfo[tokenId];
    }

    function getUserStakedTokens(
        address user
    ) external view returns (uint256[] memory) {
        return userStakedTokens[user].values();
    }

    function getStakingConfig() external view returns (StakingConfig memory) {
        return stakingConfig;
    }

    function getFixedStakingDurations()
        external
        view
        returns (uint256[] memory)
    {
        return stakingDurations;
    }

    function setMaxTokens(
        uint256 _maxTokens
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxTokens = _maxTokens;
    }

    function getAllStakedTokens() external view returns (uint256[] memory) {
        return allStakedTokens.values();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
