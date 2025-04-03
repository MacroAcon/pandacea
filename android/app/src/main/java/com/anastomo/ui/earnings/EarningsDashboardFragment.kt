package com.anastomo.ui.earnings

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.anastomo.R
import com.anastomo.databinding.FragmentEarningsDashboardBinding
import com.anastomo.models.EarningsLog
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

class EarningsDashboardFragment : Fragment() {
    private var _binding: FragmentEarningsDashboardBinding? = null
    private val binding get() = _binding!!

    private lateinit var earningsAdapter: EarningsAdapter
    private val currencyFormatter = NumberFormat.getCurrencyInstance().apply {
        currency = Currency.getInstance("USD")
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentEarningsDashboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setupRecyclerView()
        setupListeners()
        observeEarnings()
    }

    private fun setupRecyclerView() {
        earningsAdapter = EarningsAdapter()

        binding.earningsRecyclerView.apply {
            layoutManager = LinearLayoutManager(context)
            adapter = earningsAdapter
        }
    }

    private fun setupListeners() {
        binding.withdrawButton.setOnClickListener {
            showWithdrawalDialog()
        }

        binding.paymentHistoryButton.setOnClickListener {
            // TODO: Navigate to detailed payment history
        }

        binding.earningsChartButton.setOnClickListener {
            // TODO: Show earnings chart
        }
    }

    private fun observeEarnings() {
        lifecycleScope.launch {
            // TODO: Replace with actual earnings flow
            val sampleEarnings = listOf(
                EarningsLog(
                    logId = "1",
                    earningEventId = "event1",
                    userId = "user1",
                    deviceId = "device1",
                    queryId = "query1",
                    developerId = "dev1",
                    dataSourceId = "location",
                    dataTierUsed = 1,
                    eventTimestamp = System.currentTimeMillis(),
                    earnedAmount = 0.25,
                    currency = "USD",
                    payoutStatus = "pending"
                )
            )
            
            updateTotalEarnings(sampleEarnings)
            earningsAdapter.submitList(sampleEarnings)
            updateEmptyState(sampleEarnings.isEmpty())
        }
    }

    private fun updateTotalEarnings(earnings: List<EarningsLog>) {
        val total = earnings.sumOf { it.earnedAmount }
        binding.totalEarningsText.text = currencyFormatter.format(total)
    }

    private fun showWithdrawalDialog() {
        // TODO: Implement withdrawal dialog
        // - Show available balance
        // - Select withdrawal method
        // - Enter amount
        // - Confirm withdrawal
    }

    private fun updateEmptyState(isEmpty: Boolean) {
        binding.emptyStateGroup.visibility = if (isEmpty) View.VISIBLE else View.GONE
        binding.earningsRecyclerView.visibility = if (isEmpty) View.GONE else View.VISIBLE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
} 