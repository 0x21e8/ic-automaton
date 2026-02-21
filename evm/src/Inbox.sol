// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

contract Inbox {
    uint256 public constant DEFAULT_MIN_USDC = 1_000_000; // 1 USDC (6 decimals)
    uint256 public constant DEFAULT_MIN_ETH_WEI = 500_000_000_000_000; // 0.0005 ETH

    IERC20 public immutable usdc;

    struct MinPrices {
        uint256 usdcMin;
        uint256 ethMinWei;
        bool isCustom;
    }

    mapping(address => MinPrices) private minPricesByAutomaton;
    mapping(address => uint64) public nonces;

    event MinPricesUpdated(address indexed automaton, uint256 usdcMin, uint256 ethMinWei);
    event MessageQueued(
        address indexed automaton,
        uint64 indexed nonce,
        address sender,
        string message,
        uint256 usdcAmount,
        uint256 ethAmountWei
    );

    constructor(address usdcToken) {
        require(usdcToken != address(0), "usdc required");
        usdc = IERC20(usdcToken);
    }

    function setMinPrices(uint256 usdcMin, uint256 ethMinWei) external {
        minPricesByAutomaton[msg.sender] = MinPrices({
            usdcMin: usdcMin,
            ethMinWei: ethMinWei,
            isCustom: true
        });
        emit MinPricesUpdated(msg.sender, usdcMin, ethMinWei);
    }

    function minPricesFor(address automaton)
        public
        view
        returns (uint256 usdcMin, uint256 ethMinWei, bool usesDefault)
    {
        MinPrices memory minPrices = minPricesByAutomaton[automaton];
        if (!minPrices.isCustom) {
            return (DEFAULT_MIN_USDC, DEFAULT_MIN_ETH_WEI, true);
        }

        return (minPrices.usdcMin, minPrices.ethMinWei, false);
    }

    function queueMessage(address automaton, string calldata message, uint256 usdcAmount)
        external
        payable
        returns (uint64 nonce)
    {
        require(automaton != address(0), "automaton required");

        (uint256 minUsdc, uint256 minEthWei,) = minPricesFor(automaton);
        require(usdcAmount >= minUsdc, "insufficient usdc");
        require(msg.value >= minEthWei, "insufficient eth");

        _safeTransferFrom(address(usdc), msg.sender, address(this), usdcAmount);
        _safeTransfer(address(usdc), automaton, usdcAmount);

        (bool sent,) = automaton.call{value: msg.value}("");
        require(sent, "eth forward failed");

        nonce = nonces[automaton] + 1;
        nonces[automaton] = nonce;

        emit MessageQueued(automaton, nonce, msg.sender, message, usdcAmount, msg.value);
    }

    function _safeTransferFrom(address token, address from, address to, uint256 value) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "transferFrom failed");
    }

    function _safeTransfer(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }
}
