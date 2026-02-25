// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Inbox} from "../src/Inbox.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address msgSender) external;
    function expectRevert(bytes calldata revertData) external;
}

contract EthReceiver {
    receive() external payable {}
}

contract InboxTest {
    Vm private constant vm = Vm(VM_ADDRESS);

    MockUSDC private usdc;
    Inbox private inbox;

    address private constant PAYER = address(0xBEEF);
    address private constant AUTOMATON = address(0xA11CE);
    uint256 private constant DEFAULT_USDC_MIN = 1_000_000;
    uint256 private constant DEFAULT_ETH_MIN = 500_000_000_000_000;

    function setUp() public {
        usdc = new MockUSDC();
        inbox = new Inbox(address(usdc));

        usdc.mint(PAYER, 100_000_000);
        vm.deal(PAYER, 100 ether);
        vm.prank(PAYER);
        usdc.approve(address(inbox), type(uint256).max);
    }

    function test_DefaultMinPricesWhenUnset() public {
        (uint256 usdcMin, uint256 ethMinWei, bool usesDefault) = inbox.minPricesFor(AUTOMATON);

        _assertEq(usdcMin, DEFAULT_USDC_MIN, "unexpected default usdc min");
        _assertEq(ethMinWei, DEFAULT_ETH_MIN, "unexpected default eth min");
        _assertTrue(usesDefault, "expected default min-prices");
    }

    function test_AutomatonSetsOwnMinPricesWithoutAffectingOthers() public {
        vm.prank(AUTOMATON);
        inbox.setMinPrices(2_500_000, 1_000_000_000_000_000);

        (uint256 usdcMin, uint256 ethMinWei, bool usesDefault) = inbox.minPricesFor(AUTOMATON);
        _assertEq(usdcMin, 2_500_000, "automaton usdc min mismatch");
        _assertEq(ethMinWei, 1_000_000_000_000_000, "automaton eth min mismatch");
        _assertTrue(!usesDefault, "automaton should use override");

        address otherAutomaton = address(0xCAFE);
        vm.prank(otherAutomaton);
        inbox.setMinPrices(9_000_000, 2_000_000_000_000_000);

        (uint256 afterUsdcMin, uint256 afterEthMinWei,) = inbox.minPricesFor(AUTOMATON);
        _assertEq(afterUsdcMin, 2_500_000, "other sender overwrote automaton usdc min");
        _assertEq(afterEthMinWei, 1_000_000_000_000_000, "other sender overwrote automaton eth min");
    }

    function test_QueueMessageForwardsUsdcAndEthAndTracksNonce() public {
        EthReceiver automaton = new EthReceiver();
        address automatonAddress = address(automaton);

        uint256 usdcAmount = 1_250_000;
        uint256 ethAmount = 1_000_000_000_000_000; // 0.001 ETH

        vm.prank(PAYER);
        uint64 nonce1 = inbox.queueMessage{value: ethAmount}(automatonAddress, "hello", usdcAmount);
        _assertEq(uint256(nonce1), 1, "first nonce mismatch");
        _assertEq(uint256(inbox.nonces(automatonAddress)), 1, "stored first nonce mismatch");
        _assertEq(usdc.balanceOf(automatonAddress), usdcAmount, "usdc was not forwarded");
        _assertEq(automatonAddress.balance, ethAmount, "eth was not forwarded");

        vm.prank(PAYER);
        uint64 nonce2 = inbox.queueMessage{value: ethAmount}(automatonAddress, "world", usdcAmount);
        _assertEq(uint256(nonce2), 2, "second nonce mismatch");
        _assertEq(uint256(inbox.nonces(automatonAddress)), 2, "stored second nonce mismatch");
        _assertEq(usdc.balanceOf(automatonAddress), usdcAmount * 2, "second usdc forward mismatch");
        _assertEq(automatonAddress.balance, ethAmount * 2, "second eth forward mismatch");
    }

    function test_NoRegistrationRequiredForNewAutomaton() public {
        EthReceiver automaton = new EthReceiver();
        address automatonAddress = address(automaton);

        (uint256 usdcMin, uint256 ethMinWei, bool usesDefault) = inbox.minPricesFor(automatonAddress);
        _assertEq(usdcMin, DEFAULT_USDC_MIN, "new automaton default usdc mismatch");
        _assertEq(ethMinWei, DEFAULT_ETH_MIN, "new automaton default eth mismatch");
        _assertTrue(usesDefault, "new automaton should use defaults");

        vm.prank(PAYER);
        inbox.queueMessage{value: DEFAULT_ETH_MIN}(automatonAddress, "no registration", DEFAULT_USDC_MIN);
        _assertEq(uint256(inbox.nonces(automatonAddress)), 1, "message should queue without registration");
    }

    function test_QueueMessageUsesOverrideThresholds() public {
        address automaton = address(0xC0DE);

        vm.prank(automaton);
        inbox.setMinPrices(3_000_000, 2_000_000_000_000_000);

        vm.expectRevert(
            abi.encodeWithSelector(Inbox.InsufficientUSDC.selector, uint256(2_999_999), uint256(3_000_000))
        );
        vm.prank(PAYER);
        inbox.queueMessage{value: 2_000_000_000_000_000}(automaton, "underfunded usdc", 2_999_999);

        vm.expectRevert(
            abi.encodeWithSelector(
                Inbox.InsufficientETH.selector, uint256(1_999_999_999_999_999), uint256(2_000_000_000_000_000)
            )
        );
        vm.prank(PAYER);
        inbox.queueMessage{value: 1_999_999_999_999_999}(automaton, "underfunded eth", 3_000_000);

        vm.prank(PAYER);
        inbox.queueMessage{value: 2_000_000_000_000_000}(automaton, "meets override", 3_000_000);
        _assertEq(uint256(inbox.nonces(automaton)), 1, "override thresholds should allow exact payment");
    }

    function test_QueueMessageEthOnlyForwardsEthAndSkipsUsdc() public {
        EthReceiver automaton = new EthReceiver();
        address automatonAddress = address(automaton);
        uint256 payerUsdcBefore = usdc.balanceOf(PAYER);

        vm.prank(PAYER);
        uint64 nonce = inbox.queueMessageEth{value: DEFAULT_ETH_MIN}(automatonAddress, "eth only");

        _assertEq(uint256(nonce), 1, "eth-only nonce mismatch");
        _assertEq(uint256(inbox.nonces(automatonAddress)), 1, "eth-only stored nonce mismatch");
        _assertEq(usdc.balanceOf(automatonAddress), 0, "eth-only should not transfer usdc");
        _assertEq(usdc.balanceOf(PAYER), payerUsdcBefore, "eth-only should not debit payer usdc");
        _assertEq(automatonAddress.balance, DEFAULT_ETH_MIN, "eth-only should forward eth");
    }

    function test_QueueMessageEthOnlyRequiresEthMin() public {
        EthReceiver automaton = new EthReceiver();
        address automatonAddress = address(automaton);

        vm.expectRevert(
            abi.encodeWithSelector(
                Inbox.InsufficientETH.selector, uint256(DEFAULT_ETH_MIN - 1), uint256(DEFAULT_ETH_MIN)
            )
        );
        vm.prank(PAYER);
        inbox.queueMessageEth{value: DEFAULT_ETH_MIN - 1}(automatonAddress, "underfunded eth only");
    }

    function _assertEq(uint256 lhs, uint256 rhs, string memory reason) private pure {
        require(lhs == rhs, reason);
    }

    function _assertTrue(bool value, string memory reason) private pure {
        require(value, reason);
    }
}
