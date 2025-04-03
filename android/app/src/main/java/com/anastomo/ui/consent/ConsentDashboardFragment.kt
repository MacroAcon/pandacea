package com.anastomo.ui.consent

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.anastomo.R
import com.anastomo.consent.ConsentManager
import com.anastomo.databinding.FragmentConsentDashboardBinding
import com.anastomo.models.Consent
import com.anastomo.models.DataSource
import com.anastomo.models.PurposeTag
import kotlinx.coroutines.launch

class ConsentDashboardFragment : Fragment() {
    private var _binding: FragmentConsentDashboardBinding? = null
    private val binding get() = _binding!!

    private lateinit var consentManager: ConsentManager
    private lateinit var consentAdapter: ConsentAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentConsentDashboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        consentManager = ConsentManager.getInstance(requireContext())
        setupRecyclerView()
        loadConsents()
        setupListeners()
    }

    private fun setupRecyclerView() {
        consentAdapter = ConsentAdapter(
            onConsentRevoked = { consentId ->
                lifecycleScope.launch {
                    consentManager.revokeConsent(consentId)
                    loadConsents()
                }
            }
        )

        binding.consentRecyclerView.apply {
            layoutManager = LinearLayoutManager(context)
            adapter = consentAdapter
        }
    }

    private fun loadConsents() {
        lifecycleScope.launch {
            val consents = consentManager.getActiveConsents()
            consentAdapter.submitList(consents)
            updateEmptyState(consents.isEmpty())
        }
    }

    private fun setupListeners() {
        binding.addConsentButton.setOnClickListener {
            showAddConsentDialog()
        }

        binding.consentHistoryButton.setOnClickListener {
            // TODO: Navigate to consent history screen
        }
    }

    private fun showAddConsentDialog() {
        // TODO: Implement consent creation dialog
        // - Show data source selection
        // - Show purpose tag selection
        // - Configure data tier
        // - Configure partner tier
        // - Set granularity options
        // - Set expiration
    }

    private fun updateEmptyState(isEmpty: Boolean) {
        binding.emptyStateGroup.visibility = if (isEmpty) View.VISIBLE else View.GONE
        binding.consentRecyclerView.visibility = if (isEmpty) View.GONE else View.VISIBLE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
} 