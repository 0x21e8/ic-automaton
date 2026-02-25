// SPDX-License-Identifier: MIT
pragma solidity 0.8.32;

/// @title Minimal ERC-20 interface used by the Inbox contract
interface IERC20 {
    /// @notice Move tokens from one account to another using allowance
    /// @param from Source address
    /// @param to Destination address
    /// @param value Amount to transfer
    /// @return success True if the transfer succeeded
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title Automaton Inbox
/// @author ic-automaton contributors
/// @notice Accepts paid messages for an automaton address and forwards payment immediately.
/// @dev `setMinPrices` is intentionally self-scoped: each caller can only change its own minimums.
contract Inbox {
    /// @notice Raised when a required address input is zero.
    error InvalidAddress();
    /// @notice Raised when `usdcToken` is not a deployed contract.
    error InvalidTokenContract(address token);
    /// @notice Raised when a message exceeds `MAX_MESSAGE_LENGTH`.
    error MessageTooLong(uint256 length, uint256 maxLength);
    /// @notice Raised when USDC payment is below automaton minimum.
    error InsufficientUSDC(uint256 provided, uint256 required);
    /// @notice Raised when ETH payment is below automaton minimum.
    error InsufficientETH(uint256 provided, uint256 required);
    /// @notice Raised when forwarding ETH to the automaton fails.
    error ETHTransferFailed();
    /// @notice Raised when low-level ERC-20 transfer call fails.
    error TransferFailed();
    /// @notice Raised when a reentrant call is attempted.
    error ReentrancyBlocked();

    /// @notice Hard cap for message body length.
    uint256 public constant MAX_MESSAGE_LENGTH = 4_096; // mirrors MAX_INBOX_BODY_CHARS in the backend
    /// @notice Default minimum USDC (6 decimals) required by `queueMessage`.
    uint256 public constant DEFAULT_MIN_USDC = 1_000_000; // 1 USDC (6 decimals)
    /// @notice Default minimum ETH required by both queue paths.
    uint256 public constant DEFAULT_MIN_ETH_WEI = 500_000_000_000_000; // 0.0005 ETH

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    /// @notice ERC-20 token used for USDC path payments.
    IERC20 public immutable usdc;
    uint256 private _reentrancyStatus;

    /// @notice Per-automaton minimum payment configuration.
    struct MinPrices {
        uint256 usdcMin;
        uint256 ethMinWei;
        bool isCustom;
    }

    mapping(address automaton => MinPrices prices) private _minPricesByAutomaton;
    /// @notice Per-automaton message nonce.
    mapping(address automaton => uint64 nonce) public nonces;

    /// @notice Emitted when an automaton updates its own minimum prices.
    event MinPricesUpdated(address indexed automaton, uint256 usdcMin, uint256 ethMinWei);
    /// @notice Emitted after a message is queued successfully.
    event MessageQueued(
        address indexed automaton,
        uint64 indexed nonce,
        address sender,
        string message,
        uint256 usdcAmount,
        uint256 ethAmountWei
    );

    /// @notice Initializes the Inbox with the USDC token address.
    /// @param usdcToken ERC-20 token address used for USDC payments.
    constructor(address usdcToken) {
        if (usdcToken == address(0)) revert InvalidAddress();
        if (usdcToken.code.length == 0) revert InvalidTokenContract(usdcToken);

        usdc = IERC20(usdcToken);
        _reentrancyStatus = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        if (_reentrancyStatus == _ENTERED) revert ReentrancyBlocked();

        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    /// @notice Sets custom minimum prices for the caller's automaton address.
    /// @dev The config is keyed by `msg.sender`; callers cannot edit another automaton's settings.
    /// @param usdcMin Minimum USDC required for `queueMessage`.
    /// @param ethMinWei Minimum ETH required for both queue paths.
    function setMinPrices(uint256 usdcMin, uint256 ethMinWei) external {
        _minPricesByAutomaton[msg.sender] = MinPrices({usdcMin: usdcMin, ethMinWei: ethMinWei, isCustom: true});
        emit MinPricesUpdated(msg.sender, usdcMin, ethMinWei);
    }

    /// @notice Returns the active minimum prices for an automaton address.
    /// @param automaton Automaton address to inspect.
    /// @return usdcMin Minimum USDC required for the USDC queue path.
    /// @return ethMinWei Minimum ETH required for message queueing.
    /// @return usesDefault True when no custom minimum is configured.
    function minPricesFor(address automaton)
        public
        view
        returns (uint256 usdcMin, uint256 ethMinWei, bool usesDefault)
    {
        MinPrices storage prices = _minPricesByAutomaton[automaton];
        if (!prices.isCustom) {
            return (DEFAULT_MIN_USDC, DEFAULT_MIN_ETH_WEI, true);
        }

        return (prices.usdcMin, prices.ethMinWei, false);
    }

    /**
     * @notice Path 1: Payment via USDC
     */
    function queueMessage(address automaton, string calldata message, uint256 usdcAmount)
        external
        payable
        nonReentrant
        returns (uint64 nonce)
    {
        uint256 messageLength = bytes(message).length;
        if (automaton == address(0)) revert InvalidAddress();
        if (messageLength > MAX_MESSAGE_LENGTH) revert MessageTooLong(messageLength, MAX_MESSAGE_LENGTH);

        (uint256 minUsdc, uint256 minEthWei,) = minPricesFor(automaton);
        if (usdcAmount < minUsdc) revert InsufficientUSDC(usdcAmount, minUsdc);
        if (msg.value < minEthWei) revert InsufficientETH(msg.value, minEthWei);

        // 1. Effects: Update state before external calls (CEI Pattern)
        nonce = ++nonces[automaton];

        // 2. Interactions:
        if (usdcAmount > 0) {
            _safeTransferFrom(address(usdc), msg.sender, automaton, usdcAmount);
        }

        if (msg.value > 0) {
            (bool sent,) = automaton.call{value: msg.value}("");
            if (!sent) revert ETHTransferFailed();
        }

        emit MessageQueued(automaton, nonce, msg.sender, message, usdcAmount, msg.value);
    }

    /**
     * @notice Path 2: Payment via ETH only (ignores USDC requirements)
     */
    function queueMessageEth(address automaton, string calldata message)
        external
        payable
        nonReentrant
        returns (uint64 nonce)
    {
        uint256 messageLength = bytes(message).length;
        if (automaton == address(0)) revert InvalidAddress();
        if (messageLength > MAX_MESSAGE_LENGTH) revert MessageTooLong(messageLength, MAX_MESSAGE_LENGTH);

        (, uint256 minEthWei,) = minPricesFor(automaton);
        if (msg.value < minEthWei) revert InsufficientETH(msg.value, minEthWei);

        // 1. Effects:
        nonce = ++nonces[automaton];

        // 2. Interactions:
        if (msg.value > 0) {
            (bool sent,) = automaton.call{value: msg.value}("");
            if (!sent) revert ETHTransferFailed();
        }

        emit MessageQueued(automaton, nonce, msg.sender, message, 0, msg.value);
    }

    // --- Internal Helpers ---
    function _safeTransferFrom(address token, address from, address to, uint256 value) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value));
        if (!(success && (data.length == 0 || abi.decode(data, (bool))))) revert TransferFailed();
    }
}
