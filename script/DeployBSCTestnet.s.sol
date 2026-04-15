// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AgenticCommerceHooked} from "../contracts/AgenticCommerceHooked.sol";
import {TrustGateACPHook} from "../contracts/hooks/TrustGateACPHook.sol";
import {TrustBasedEvaluator} from "../contracts/hooks/TrustBasedEvaluator.sol";
import {AttestationHook} from "../contracts/hooks/AttestationHook.sol";
import {EvaluatorRegistry} from "../contracts/EvaluatorRegistry.sol";
import {CompositeRouterHook} from "../contracts/hooks/CompositeRouterHook.sol";
import {TrustUpdateHook} from "../contracts/hooks/TrustUpdateHook.sol";
import {MutualAttestationHook} from "../contracts/hooks/MutualAttestationHook.sol";

/// @title DeployBSCTestnet
/// @notice Deploys AgenticCommerceHooked + all Maiat trust hooks on BSC testnet (chain 97)
///
/// Usage:
///   forge script script/DeployBSCTestnet.s.sol \
///     --rpc-url https://data-seed-prebsc-1-s1.binance.org:8545 \
///     --private-key $PRIVATE_KEY \
///     --broadcast -vvvv
///
/// Required env vars:
///   PRIVATE_KEY      — deployer private key
///   MOCK_USDC        — MockUSDC address from DeployTestnet run
///   TRUST_ORACLE     — DojoTrustScore address from DeployTestnet run
///
/// Optional:
///   BAS_CONTRACT     — BAS/EAS contract address on BSC testnet (for AttestationHook)
///   BAS_SCHEMA_UID   — pre-registered BAS schema UID
///
contract DeployBSCTestnet is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        address mockUSDC   = vm.envAddress("MOCK_USDC");
        address trustOracle = vm.envAddress("TRUST_ORACLE");

        // Optional: AttestationHook (skip if no BAS contract set)
        address basContract = vm.envOr("BAS_CONTRACT", address(0));
        bytes32 basSchemaUID = vm.envOr("BAS_SCHEMA_UID", bytes32(0));

        console2.log("=== Maiat ACP Hooks - BSC Testnet Deploy ===");
        console2.log("Deployer:     ", deployer);
        console2.log("Chain ID:     ", block.chainid);
        console2.log("MockUSDC:     ", mockUSDC);
        console2.log("TrustOracle:  ", trustOracle);

        vm.startBroadcast(deployerKey);

        // 0. AgenticCommerceHooked — core ACP contract (hooks plug into this)
        AgenticCommerceHooked acp = new AgenticCommerceHooked(mockUSDC, deployer);
        console2.log("\n0. AgenticCommerceHooked:", address(acp));

        // 1. TrustGateACPHook (upgradeable)
        //    Blocks agents with trust score < 60 from opening/taking jobs
        address trustGate;
        {
            TrustGateACPHook impl = new TrustGateACPHook();
            bytes memory initData = abi.encodeCall(
                TrustGateACPHook.initialize,
                (trustOracle, address(acp), 60, 60, deployer)
            );
            trustGate = address(new ERC1967Proxy(address(impl), initData));
            console2.log("1. TrustGateACPHook:    ", trustGate);
        }

        // 2. TrustBasedEvaluator (upgradeable)
        //    Auto-evaluates job completion based on trust score >= 60
        address evaluator;
        {
            TrustBasedEvaluator impl = new TrustBasedEvaluator();
            bytes memory initData = abi.encodeCall(
                TrustBasedEvaluator.initialize,
                (trustOracle, address(acp), 60, deployer)
            );
            evaluator = address(new ERC1967Proxy(address(impl), initData));
            console2.log("2. TrustBasedEvaluator: ", evaluator);
        }

        // 3. EvaluatorRegistry (upgradeable)
        //    Tracks per-domain evaluator assignments + success rates
        address registry;
        {
            EvaluatorRegistry impl = new EvaluatorRegistry();
            bytes memory initData = abi.encodeCall(EvaluatorRegistry.initialize, (deployer));
            registry = address(new ERC1967Proxy(address(impl), initData));
            console2.log("3. EvaluatorRegistry:   ", registry);
        }

        // 4. CompositeRouterHook (upgradeable)
        //    Orchestrates plugin execution (beforeAction / afterAction)
        address router;
        {
            CompositeRouterHook impl = new CompositeRouterHook();
            bytes memory initData = abi.encodeCall(
                CompositeRouterHook.initialize,
                (address(acp), deployer)
            );
            router = address(new ERC1967Proxy(address(impl), initData));

            // Wire TrustGate in as plugin priority 10
            CompositeRouterHook(router).addPlugin(trustGate, 10);
            console2.log("4. CompositeRouterHook: ", router);
        }

        // 5. AttestationHook (non-upgradeable) — optional, needs BAS contract
        address attestation;
        if (basContract != address(0) && basSchemaUID != bytes32(0)) {
            attestation = address(new AttestationHook(address(acp), basContract, basSchemaUID));
            CompositeRouterHook(router).addPlugin(attestation, 30);
            console2.log("5. AttestationHook:     ", attestation);
        } else {
            console2.log("5. AttestationHook:      SKIPPED (set BAS_CONTRACT + BAS_SCHEMA_UID)");
        }

        // 6. TrustUpdateHook (non-upgradeable)
        //    Calls DojoTrustScore.updateScore() after closeAndSettle completes/rejects
        TrustUpdateHook trustUpdate = new TrustUpdateHook(address(acp), trustOracle);
        CompositeRouterHook(router).addPlugin(address(trustUpdate), 20);
        console2.log("6. TrustUpdateHook:     ", address(trustUpdate));

        // 7. MutualAttestationHook (non-upgradeable) — optional, needs BAS contract
        //    Airbnb-style mutual reviews: client + provider attest each other post-settlement
        address mutualAttest;
        if (basContract != address(0) && basSchemaUID != bytes32(0)) {
            mutualAttest = address(new MutualAttestationHook(
                address(acp),
                basContract,
                basSchemaUID,
                7 days
            ));
            CompositeRouterHook(router).addPlugin(mutualAttest, 25);
            console2.log("7. MutualAttestationHook:", mutualAttest);
        } else {
            console2.log("7. MutualAttestationHook: SKIPPED (set BAS_CONTRACT + BAS_SCHEMA_UID)");
        }

        vm.stopBroadcast();

        console2.log("\n=== BSC Testnet Addresses ===");
        console2.log("AgenticCommerceHooked: ", address(acp));
        console2.log("TrustGateACPHook:      ", trustGate);
        console2.log("TrustBasedEvaluator:   ", evaluator);
        console2.log("EvaluatorRegistry:     ", registry);
        console2.log("CompositeRouterHook:   ", router);
        if (attestation != address(0)) {
            console2.log("AttestationHook:       ", attestation);
        }
        console2.log("TrustUpdateHook:       ", address(trustUpdate));
        if (mutualAttest != address(0)) {
            console2.log("MutualAttestationHook: ", mutualAttest);
        }

        console2.log("\nPost-deploy:");
        console2.log("  1. Set CompositeRouterHook as ACP hook for new jobs");
        console2.log("  2. Register TrustBasedEvaluator: registry.register('dojo', evaluator)");
        console2.log("  3. Grant EVALUATOR_ROLE on DojoTrustScore to TrustUpdateHook");
        console2.log("  4. Call acp.setTrustedGateway(gateway) for closeAndSettle verification");
        console2.log("  5. Seed test scores on DojoTrustScore, then create an ACP job");
    }
}
