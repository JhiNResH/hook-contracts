// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/hooks/TokenSafetyHook.sol";
import "../contracts/interfaces/ITokenSafetyOracle.sol";
import "@acp/AgenticCommerce.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock oracle that returns configurable verdicts
contract MockOracle is ITokenSafetyOracle {
    mapping(address => TokenSafetyData) private _verdicts;

    function setVerdict(address token, TokenVerdict verdict) external {
        _verdicts[token] = TokenSafetyData({
            verdict: verdict,
            buyTax: 0,
            sellTax: 0,
            verified: true,
            lastUpdated: block.timestamp
        });
    }

    function getTokenSafety(address token) external view returns (TokenSafetyData memory) {
        return _verdicts[token];
    }
}

/// @dev Minimal ERC20 for testing
contract MockToken is ERC20 {
    constructor(string memory name) ERC20(name, name) {
        _mint(msg.sender, 1_000_000e18);
    }
}

contract TokenSafetyHookTest is Test {
    TokenSafetyHook hook;
    AgenticCommerce acp;
    MockOracle oracle;
    MockToken goodToken;
    MockToken badToken;

    address owner = makeAddr("owner");
    address client = makeAddr("client");
    address provider = makeAddr("provider");

    function setUp() public {
        // Deploy ACP
        vm.startPrank(owner);
        AgenticCommerce impl = new AgenticCommerce();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(AgenticCommerce.initialize, (owner))
        );
        acp = AgenticCommerce(address(proxy));

        // Deploy oracle + tokens
        oracle = new MockOracle();
        goodToken = new MockToken("GOOD");
        badToken = new MockToken("BAD");

        // Configure oracle verdicts
        oracle.setVerdict(address(goodToken), ITokenSafetyOracle.TokenVerdict.Safe);
        oracle.setVerdict(address(badToken), ITokenSafetyOracle.TokenVerdict.Honeypot);

        // Deploy hook
        hook = new TokenSafetyHook(address(acp), address(oracle), 0, owner);

        // Whitelist hook on ACP
        acp.setHookWhitelist(address(hook), true);
        vm.stopPrank();

        // Fund client with tokens
        vm.prank(owner);
        goodToken.transfer(client, 10_000e18);
        vm.prank(owner);
        badToken.transfer(client, 10_000e18);
    }

    // ──────── Core: safe token passes ────────

    function test_safeToken_passes() public {
        // Create job + set budget with good token
        vm.startPrank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(hook), 0);
        acp.setBudget(jobId, address(goodToken), 100e18, "");
        goodToken.approve(address(acp), 100e18);

        // fund() should succeed — oracle returns Safe
        acp.fund(jobId, 100e18, "");
        vm.stopPrank();
    }

    // ──────── Core: honeypot token reverts ────────

    function test_honeypotToken_reverts() public {
        vm.startPrank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(hook), 0);
        acp.setBudget(jobId, address(badToken), 100e18, "");
        badToken.approve(address(acp), 100e18);

        // fund() should revert — oracle returns Honeypot
        vm.expectRevert(abi.encodeWithSelector(TokenSafetyHook.UnsafeToken.selector, address(badToken), 1));
        acp.fund(jobId, 100e18, "");
        vm.stopPrank();
    }

    // ──────── Whitelist bypasses oracle ────────

    function test_whitelisted_bypasses_oracle() public {
        // Whitelist the bad token
        vm.prank(owner);
        hook.setWhitelisted(address(badToken), true);

        vm.startPrank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(hook), 0);
        acp.setBudget(jobId, address(badToken), 100e18, "");
        badToken.approve(address(acp), 100e18);

        // Should pass despite oracle saying Honeypot
        acp.fund(jobId, 100e18, "");
        vm.stopPrank();
    }

    // ──────── No token set — skip check ────────

    function test_noPaymentToken_skips() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(hook), 0);

        // Call _preFund directly via ACP with no budget set (paymentToken = address(0))
        // This shouldn't revert
        vm.prank(address(acp));
        hook.beforeAction(jobId, bytes4(keccak256("fund(uint256,uint256,bytes)")), abi.encode(client, ""));
    }

    // ──────── Admin: blocked verdicts ────────

    function test_setBlockedVerdicts() public {
        // Allow Honeypot by clearing its bit
        vm.prank(owner);
        hook.setBlockedVerdicts((1 << 2) | (1 << 4)); // Only block HighTax + Blocked

        vm.startPrank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(hook), 0);
        acp.setBudget(jobId, address(badToken), 100e18, "");
        badToken.approve(address(acp), 100e18);

        // Honeypot now allowed
        acp.fund(jobId, 100e18, "");
        vm.stopPrank();
    }

    // ──────── Admin: only owner ────────

    function test_setOracle_revertNonOwner() public {
        vm.prank(client);
        vm.expectRevert(TokenSafetyHook.OnlyOwner.selector);
        hook.setOracle(address(oracle));
    }

    function test_setWhitelisted_revertNonOwner() public {
        vm.prank(client);
        vm.expectRevert(TokenSafetyHook.OnlyOwner.selector);
        hook.setWhitelisted(address(goodToken), true);
    }

    // ──────── View: isVerdictBlocked ────────

    function test_isVerdictBlocked() public view {
        assertTrue(hook.isVerdictBlocked(1));  // Honeypot
        assertTrue(hook.isVerdictBlocked(2));  // HighTax
        assertFalse(hook.isVerdictBlocked(0)); // Safe
        assertFalse(hook.isVerdictBlocked(3)); // Unverified
        assertTrue(hook.isVerdictBlocked(4));  // Blocked
    }

    // ──────── Batch whitelist ────────

    function test_setWhitelistedBatch() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(goodToken);
        tokens[1] = address(badToken);

        vm.prank(owner);
        hook.setWhitelistedBatch(tokens, true);

        assertTrue(hook.whitelisted(address(goodToken)));
        assertTrue(hook.whitelisted(address(badToken)));
    }
}
